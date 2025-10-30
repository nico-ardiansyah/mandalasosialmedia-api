const express = require("express");
const router = express.Router();
const multer = require("multer");
const ffmpeg = require("fluent-ffmpeg");
const plimit = require("p-limit");
const limit = plimit(10);
const stream = require("stream");
const mongoose = require("mongoose");
const { rateLimit, ipKeyGenerator } = require("express-rate-limit");
const sanitizeHtml = require("sanitize-html");

// req post limiter
const postRateLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: { message: "Too many request, please try again later" },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.user?._id || ipKeyGenerator,
});

// req get limiter
const getRateLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 15,
    message: { message: "Too many request, please try again later" },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.user?._id || ipKeyGenerator,
});




// create local dir
const upload = multer({ storage : multer.memoryStorage() });


// jwt validation
const JWTVerification = require("../../../Services/JWT/JWTVerification");

// schema
const postSchema = require("../../PostRoutes/schema/PostSchema");
const notifSchema = require("../schema/NotificationSchema");
const commentSchema = require("../schema/CommentSchema");
const fileCommentSchema = require("../schema/FileCommentSchema");
const replyCommentSchema = require("../schema/ReplyCommentSchema");
const fileReplyCommentSchema = require("../schema/FileReplyCommentSchema");
const userSchema = require("../../AuthRoutes/schema/UserSchema");

// Google Drive Config
const GDCommentConfig = require("../GoogleDriveConfig/GDFileComment");
const GDReplyCommentConfig = require("../GoogleDriveConfig/GDFileReplyComment");
const notificationSchema = require("../schema/NotificationSchema");

// liked post
router.post('/:postId/liked-post', JWTVerification, postRateLimiter, async (req, res) => { 
    const postId = req.params.postId;

    if (!mongoose.Types.ObjectId.isValid(postId)) {
        return res.status(400).json({ message: "Invalid post ID format" });
    };

    try {
        const post = await postSchema.findById(postId).populate("author");
        
        // validation post
        if (!post) return res.status(404).json({ message: "Post not found" });

        // disliked post
        if (post.likes.includes(req.user._id)) {
            await postSchema.findByIdAndUpdate(post._id, {
                $pull: { likes: req.user._id },
            });

            // deleted notification
            const notifDelete = await notifSchema.findOneAndDelete({
                post: post._id,
                recipient : post.author,
                sender: req.user._id,
                type: "like"
            });

            if (notifDelete) {
                // update userSchema
                await userSchema.findByIdAndUpdate(post.author._id, {
                    $pull: { notifications: notifDelete._id }
                });
            };


            return res.sendStatus(200)

        };

        
        // liked post
        await postSchema.findByIdAndUpdate(post._id, {
            $addToSet: { likes: req.user._id }
        });

        // notification
        if (String(post.author._id) !== String(req.user._id)) { 
            const notif = new notifSchema({
                post: post._id,
                recipient: post.author,
                sender: req.user._id,
                type: "like",
                message: `${req.user.username} liked your post`
            });

            await notif.save();

            // update userSchema
            await userSchema.findByIdAndUpdate(post.author._id, {
                $push: { notifications: notif._id }
            });
        };
        

        return res.sendStatus(200);


    } catch (e) {
        console.error(e)
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    };
});

// comment
router.post("/:postId/upload-comment", JWTVerification, postRateLimiter, upload.single("file"), async (req, res) => {
    const { content } = req.body;
    const postId = req.params.postId;
    const file = req.file;

    if (!mongoose.Types.ObjectId.isValid(postId)) {
        return res.status(400).json({ error: "Invalid post ID format" });
    };

    
    // validation
    if ((!content || !content.trim()) && !file) {
        return res.status(400).json({ error: "Content or File is required" });
    };
    if (content && content.length > 500) {
        return res.status(400).json({ error: "Content too long (max 500 characters)" });
    };

    if (file) {
        // validation image
        if (!file.mimetype.startsWith("image/")) {
            return res.status(400).json({ error: "Only image can uploaded" });
        };

        if (file.size > 2 * 1024 * 1024) {
            return res.status(400).json({ error: `Your file size too large (max 2MB)` });
        }
    };
    
    const cleanContent = sanitizeHtml(content || "", { allowedTags: [], allowedAttributes: {} }).trim();

    const session = await mongoose.startSession();
    session.startTransaction();

    let uploadFileId;

    try {
        // validation post
        const post = await postSchema.findById(postId).populate("author");

        if (!post) {
            return res.status(404).json({ message: "Post not found" });
        };

        // create comment
        const [uploadComment] = await commentSchema.create(
            [{ 
                post: post._id,
                author: req.user._id,
                content: cleanContent || null
            }],
            {session}
        );

        await postSchema.findByIdAndUpdate(postId,
            { $addToSet: { comments: uploadComment._id } },
            { session }
        );


        // notification
        if (String(post.author._id) !== String(req.user._id)) { 
            const [notif] = await notifSchema.create(
                [{
                    post: post._id,
                    recipient: post.author,
                    sender: req.user._id,
                    type: "comment",
                    message: `${req.user.username} commented your post`
                }],
                { session }
            );

            // update userSchema
            await userSchema.findByIdAndUpdate(post.author._id,
                { $push: { notifications: notif._id } },
                { session }
            );
        };
        
        if (!file) {
            await session.commitTransaction();
            return res.sendStatus(200)
        };
        

        // upload file
        const savedFile = await Promise.all([
            (async () => { 
                // getting readable file from buffer file
                const uploadBuffer = new stream.PassThrough();
                uploadBuffer.end(file.buffer);

                try {
                    const uploadFile = await GDCommentConfig.files.create({
                        requestBody: {
                            name: file.originalname,
                            parents : [process.env.FOLDER_COMMENT_ID]
                        },
                        media: {
                            mimeType: file.mimetype,
                            body: uploadBuffer,
                        },
                        fields: "id, size, name, mimeType",
                    });

                    uploadFileId = uploadFile.data.id;

                        // give permission file
                    await GDCommentConfig.permissions.create(
                        {
                            fileId: uploadFile.data.id,
                            requestBody: {
                                role: "reader",
                                type: "anyone",
                            }
                        }
                    );

                    const [File] = await fileCommentSchema.create(
                        [{
                            author: req.user._id,
                            comment : uploadComment._id,
                            fileId: uploadFile.data.id,
                            fileName: uploadFile.data.name,
                            fileType: uploadFile.data.mimeType,
                            fileSize: uploadFile.data.size
                        }],
                        { session }
                    );

                    return File;

                } catch (e) {
                    throw new Error(`Failed upload file to google drive: ${e}`);
                };
            })()
        ]);

        // update commentSchema
        await commentSchema.findByIdAndUpdate(uploadComment._id,
            { $set: { file: savedFile[0]._id } },
            { session }
        );

        await session.commitTransaction();

        return res.sendStatus(201);

    } catch (e) {
        await session.abortTransaction();

        try { 
            await GDCommentConfig.files.delete({ fileId: uploadFileId });
        } catch (e) {
            console.warn(`⚠️ Failed to delete file ${uploadFileId} from Drive during rollback`);
        };

        console.error(e);
        return res.status(500).json({ message: "Something went wrong, please try again later" });

    } finally {
        session.endSession();
    };
});


// liked comment
router.post('/:commentId/liked-comment', JWTVerification, postRateLimiter, async (req, res) => { 
    const commentId = req.params.commentId;

    if (!mongoose.Types.ObjectId.isValid(commentId)) {
        return res.status(400).json({ message: "Invalid post ID format" });
    };

    try {
        const comment = await commentSchema.findById(commentId).populate("author");
        
        // validation comment
        if (!comment) return res.status(404).json({ message: "Comment not found" });

        // disliked comment
        if (comment.likes.includes(req.user._id)) {
            await commentSchema.findByIdAndUpdate(comment._id, {
                $pull: { likes: req.user._id },
            });

            // deleted notification
            const notifDelete = await notifSchema.findOneAndDelete({
                comment: comment._id,
                recipient : comment.author,
                sender: req.user._id,
                type: "like"
            });

            if (notifDelete) { 
                // update userSchema
                await userSchema.findByIdAndUpdate(comment.author._id, {
                    $pull: { notifications: notifDelete._id }
                });
            };


            return res.sendStatus(200)

        };

        
        // liked comment
        await commentSchema.findByIdAndUpdate(comment._id, {
            $addToSet: { likes: req.user._id }
        });

        // notification
        if (String(comment.author._id) !== String(req.user._id)) { 
            const notif = new notifSchema({
                comment: comment._id,
                recipient: comment.author,
                sender: req.user._id,
                type: "like",
                message: `${req.user.username} liked your comment`
            });

            await notif.save();

            // update userSchema
            await userSchema.findByIdAndUpdate(comment.author._id, {
                $push: { notifications: notif._id }
            });
        };
        

        return res.sendStatus(200);


    } catch (e) {
        console.error(e)
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    };
});

// reply comment
router.post("/:commentId/upload-replycomment", JWTVerification, postRateLimiter, upload.single("file"), async (req, res) => {
    const { content } = req.body;
    const commentId = req.params.commentId;
    const file = req.file;

    if (!mongoose.Types.ObjectId.isValid(commentId)) {
        return res.status(400).json({ error: "Invalid comment ID format" });
    };

    
    // validation
    if ((!content || !content.trim()) && !file) {
        return res.status(400).json({ error: "Content or File is required" });
    };
    if (content && content.length > 500) {
        return res.status(400).json({ error: "Content too long (max 500 characters)" });
    };

    if (file) {
        // validation image
        if (!file.mimetype.startsWith("image/")) {
            return res.status(400).json({ error: "Only image can uploaded" });
        };

        if (file.size > 2 * 1024 * 1024) {
            return res.status(400).json({ error: `Your file size too large (max 2MB)` });
        }
    };
    
    const cleanContent = sanitizeHtml(content || "", { allowedTags: [], allowedAttributes: {} }).trim();

    const session = await mongoose.startSession();
    session.startTransaction();

    let uploadFileId;

    try {
        // validation comment
        const comment = await commentSchema.findById(commentId).populate("author");

        if (!comment) {
            return res.status(404).json({ message: "Comment not found" });
        };

        // create replycomment
        const [uploadReplyComment] = await replyCommentSchema.create(
            [{
                comment: comment._id,
                author: req.user._id,
                content: cleanContent || null
            }],
            { session }
        );

        // notification
        if (String(comment.author._id) !== String(req.user._id)) {
            const [notif] = await notifSchema.create(
                [{
                    recipient: comment.author._id,
                    type: "replycomment",
                    sender: req.user._id,
                    replyComment: uploadReplyComment._id,
                    message: `${req.user.username} replied to your comment`
                }],
                { session }
            );

            // update userSchema
            await userSchema.findByIdAndUpdate(comment.author._id,
                { $push: { notifications: notif._id } },
                { session }
            );
        };

        await commentSchema.findByIdAndUpdate(commentId,
            { $addToSet: { replyComments: uploadReplyComment._id } },
            { session }
        );
        
        if (!file) {
            await session.commitTransaction();
            return res.sendStatus(200)
        };
        
        // upload file
        try {
            // getting readable file from buffer file
            const uploadBuffer = new stream.PassThrough();
            uploadBuffer.end(file.buffer);

            const uploadFile = await GDReplyCommentConfig.files.create({
                requestBody: {
                    name: file.originalname,
                    parents : [process.env.FOLDER_REPLYCOMMENT_ID]
                },
                media: {
                    mimeType: file.mimetype,
                    body: uploadBuffer,
                },
                fields: "id, size, name, mimeType",
            });

            uploadFileId = uploadFile.data.id
            
            // give permission file
            await GDReplyCommentConfig.permissions.create({
                fileId: uploadFile.data.id,
                requestBody: {
                    role: "reader",
                    type: "anyone",
                },
            });

            const [savedFile] = await fileReplyCommentSchema.create(
                [{
                    author: req.user._id,
                    replyComment: uploadReplyComment._id,
                    fileId: uploadFile.data.id,
                    fileName: uploadFile.data.name,
                    fileType: uploadFile.data.mimeType,
                    fileSize: uploadFile.data.size
                }],
                { session }
            );

            // update reply comment
            await replyCommentSchema.findByIdAndUpdate(uploadReplyComment._id,
                { $set: { file: savedFile._id } },
                { session }
            );


        } catch (e) {
            throw new Error(`Failed upload file to google drive: ${e}`);
        };

        await session.commitTransaction();

        return res.sendStatus(201);

    } catch (e) {
        await session.abortTransaction();

        try { 
            await GDReplyCommentConfig.files.delete({ fileId: uploadFileId });
        } catch (e) {
            console.warn(`⚠️ Failed to delete file ${uploadFileId} from Drive during rollback`);
        };

        console.error(e);
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    }
});

// liked reply comment
router.post('/:replycommentId/liked-replycomment', JWTVerification, postRateLimiter, async (req, res) => { 
    const replycommentId = req.params.replycommentId;

    if (!mongoose.Types.ObjectId.isValid(replycommentId)) {
        return res.status(400).json({ message: "Invalid post ID format" });
    };

    try {
        const replycomment = await replyCommentSchema.findById(replycommentId).populate("author");
        
        // validation comment
        if (!replycomment) return res.status(404).json({ message: "Replycomment not found" });

        // disliked replycomment
        if (replycomment.likes.includes(req.user._id)) {
            await replyCommentSchema.findByIdAndUpdate(replycomment._id, {
                $pull: { likes: req.user._id },
            });

            // deleted notification
            const notifDelete = await notifSchema.findOneAndDelete({
                replyComment: replycomment._id,
                recipient : replycomment.author,
                sender: req.user._id,
                type: "like"
            });

            if (notifDelete) { 
                // update userSchema
                await userSchema.findByIdAndUpdate(replycomment.author._id, {
                    $pull: { notifications: notifDelete._id }
                });
            };


            return res.sendStatus(200);

        };

        
        // liked comment
        await replyCommentSchema.findByIdAndUpdate(replycomment._id, {
            $addToSet: { likes: req.user._id }
        });

        // notification
        if (String(replycomment.author._id) !== String(req.user._id)) { 
            const notif = new notifSchema({
                replyComment: replycomment._id,
                recipient: replycomment.author,
                sender: req.user._id,
                type: "like",
                message: `${req.user.username} liked your replycomment`
            });

            await notif.save();

            // update userSchema
            await userSchema.findByIdAndUpdate(replycomment.author._id, {
                $push: { notifications: notif._id }
            });
        };
        

        return res.sendStatus(200);


    } catch (e) {
        console.error(e)
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    };
});

// delete comment
router.delete("/delete-comment/:commentId", JWTVerification, postRateLimiter, async (req, res) => { 
    const commentId = req.params.commentId;

    if (!mongoose.Types.ObjectId.isValid(commentId)) {
        return res.status(400).json({ message: "Invalid post ID format" });
    };

    try {
        const comment = await commentSchema.findById(commentId).populate("file").populate("author").populate("post")
        
        if (!comment) return res.status(404).json({ message: "Comment not found" });

        if (String(comment.author._id) !== String(req.user._id)) {
            return res.status(403).json({ message: "You are not allowed to delete this comment" });
        };

        const replies = await replyCommentSchema.find({ comment: comment._id }).populate("file");

        // delete replycomment
        await Promise.all(replies.map(reply => limit(async () => { 
            if (reply.file?._id) {
                try {
                    await GDReplyCommentConfig.files.delete({ fileId: reply.file.fileId });
                } catch (e) {
                    console.warn(`⚠️ Failed to delete reply file ${reply.file.fileId}:`, e.message);
                }
                await fileReplyCommentSchema.findByIdAndDelete(reply.file._id);
            };
            await replyCommentSchema.findByIdAndDelete(reply._id);
        })));

        // delete comment
        if (comment.file) {
            try {
                await GDCommentConfig.files.delete({ fileId : comment.file.fileId});
            } catch (e) {
                console.warn(`⚠️ Failed to delete comment file ${comment.file.fileId}:`, e.message);
            }
            await fileCommentSchema.findByIdAndDelete(comment.file._id);
        };

        await postSchema.findByIdAndUpdate(comment.post._id, {
            $pull: { comments: comment._id }
        });
        
        await commentSchema.findByIdAndDelete(comment._id);
        
        return res.sendStatus(200);

    } catch (e) {
        console.log(e)
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    };
});

// read notification
router.patch("/read-notification/:id", JWTVerification, postRateLimiter, async (req, res) => { 
    const notifId = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(notifId)) {
        return res.status(400).json({ message: "Invalid post ID format" });
    };

    try {
        const notification = await notificationSchema.findById(notifId);

        if (!notification) return res.status(404).json({ message: "Notification not found" });
        
        if (String(notification.recipient) !== String(req.user._id)) return res.status(403).json({ message: "You are not allowed to read this notification" });

        await notificationSchema.findByIdAndUpdate(notification._id,
            { $set: { isRead: true } },
            {new : true}
        );

        return res.sendStatus(200);

    } catch (e) {
        console.log(e);
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    };
});


// get reply comment find
router.get("/comment/:Id", JWTVerification, getRateLimiter, async (req, res) => { 
    const commentId = req.params.Id;

    if (!mongoose.Types.ObjectId.isValid(commentId)) {
        return res.status(400).json({ message: "Invalid post ID format" });
    };

    try {
        const comment = await commentSchema.findById(commentId)
            .select("_id author content likes file replyComments")
            .populate({
                path: "replyComments",
                select : ("_id author content likes file "),
                options: { sort: { createdAt: -1 } },
                populate: [
                    {
                        path: "author",
                        select : ("_id username avatar"),
                    },
                    {
                        path: "file",
                        select : ("_id fileId"),
                    }]
            })
            .populate({
                path: "author",
                select : ("_id username avatar")
            })
            .populate({
                path: "file",
                select : ("_id fileId")
            })

        if (!comment) return res.status(404).json({ message: "Comment not found" });

        return res.status(200).json({ comment });

    } catch (e) {
        console.log(e);
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    };
});

// delete replycomment
router.delete("/:replycommentId/delete-replycomment", JWTVerification, postRateLimiter, async (req, res) => { 
    const replycommentId = req.params.replycommentId;

    if (!mongoose.Types.ObjectId.isValid(replycommentId)) {
        return res.status(400).json({ message: "Invalid replycomment ID format" });
    };

    try {
        const replycomment = await replyCommentSchema.findById(replycommentId).populate("author", "_id").populate("file", "fileId").populate("comment", "_id");

        if (!replycomment) return res.status(404).json({ message: "Replycomment not found" });

        if (String(replycomment.author._id) !== String(req.user._id)) {
            return res.status(403).json({ message: "You are not allowed to delete this comment" });
        };

        if (replycomment.file) { 
            try { 
                await GDReplyCommentConfig.files.delete({fileId : replycomment.file.fileId})
            } catch (e) {
                console.warn(`⚠️ Failed to delete reply file ${replycomment.file.fileId}:`, e.message);
            }
            await fileReplyCommentSchema.findByIdAndDelete(replycomment.file._id);
        };

        await commentSchema.findByIdAndUpdate(replycomment.comment._id, {
            $pull: { replyComments: replycomment._id }
        });
        
        await replyCommentSchema.findByIdAndDelete(replycomment._id);
        
        return res.sendStatus(200);


    } catch (e) {
        console.log(e)
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    }
});

// follow and unfullow
router.post("/:userId/follow", JWTVerification, postRateLimiter, async (req, res) => {
    const userId = req.params.userId;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({ message: "Invalid user ID format" });
    };

    if (userId === String(req.user._id)) return res.status(400).json({ message: "You can't follow your self" });


    try {
        const otherUser = await userSchema.findById(userId);
        const currentUser = await userSchema.findById(req.user._id)

        if (!otherUser) return res.status(404).json({ message: "User not found" });

        const isAlreadyFollowing = otherUser.followers.some(f => f.equals(currentUser._id));


        if (isAlreadyFollowing) {
            // notification delete
            const notif = await notifSchema.findOneAndDelete({
                recipient: otherUser._id,
                sender: req.user._id,
                type : "follow"
            });

            // Unfollow
            await Promise.all([
                userSchema.findByIdAndUpdate(userId, { $pull: { followers: currentUser._id } }),
                userSchema.findByIdAndUpdate(currentUser._id, { $pull: { following: userId, notifications : notif?._id } })
            ]);

            return res.sendStatus(200);

        } else {

            // notification
            const notif = await notifSchema.create({
                recipient : otherUser._id,
                sender: req.user._id,
                type: "follow",
                message : `${currentUser.username} followed you`
            });

            // Follow
            await Promise.all([
                userSchema.findByIdAndUpdate(otherUser._id, { $addToSet: { followers: currentUser._id, notifications : notif?._id } }),
                userSchema.findByIdAndUpdate(currentUser._id, { $addToSet: { following: userId } })
            ]);

            return res.sendStatus(200);
        }

    } catch (e) {
        console.log(e)
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    };
});

module.exports = router;