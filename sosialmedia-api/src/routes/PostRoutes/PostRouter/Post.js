const express = require("express");
const router = express.Router();
const multer = require("multer");
const plimit = require("p-limit");
const limit = plimit(10);
const stream = require("stream");
const { rateLimit, ipKeyGenerator } = require("express-rate-limit");
const sanitizeHtml = require("sanitize-html");
const mongoose = require("mongoose");

// req post limiter
const postRateLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: { message: "Too many request, please try again later" },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => ipKeyGenerator,
});

// req get limiter
const getRateLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 15,
    message: { message: "Too many request, please try again later" },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => ipKeyGenerator,
});


// create local dir
const upload = multer({ storage : multer.memoryStorage() });


// jwt validation
const JWTVerification = require("../../../Services/JWT/JWTVerification");

// schema
const filePostSchema = require("../schema/FilePostSchema");
const postSchema = require("../schema/PostSchema");
const userSchema = require("../../AuthRoutes/schema/UserSchema");
const commentSchema = require("../../UserAction/schema/CommentSchema");
const replyCommentSchema = require("../../UserAction/schema/ReplyCommentSchema");
const fileReplyCommentSchema = require("../../UserAction/schema/FileReplyCommentSchema");
const fileCommentSchema = require("../../UserAction/schema/FileCommentSchema");
const notificationSchema = require("../../UserAction/schema/NotificationSchema");

// Google Drive Config
const GDPostConfig = require("../GoogleDriveConfig/GDPostConfig");
const GDReplyCommentConfig = require("../../UserAction/GoogleDriveConfig/GDFileReplyComment");
const GDCommentConfig = require("../../UserAction/GoogleDriveConfig/GDFileComment");


// upload post
router.post("/upload-post", JWTVerification, postRateLimiter, upload.array("files", 5), async (req, res) => { 
    const { content } = req.body;
    const files = req.files;

    if ((!content || !content.trim()) && (!files || files.length === 0)) return res.status(400).json({ error: "Content or Files is required" });
    if (content && content.length > 300) return res.status(400).json({ error: "Content length too long (max 300 character" });

    const cleanContent = sanitizeHtml(content || "", { allowedTags: [], allowedAttributes: {} }).trim();


    // validation files
    if (files) {
        for (let file of files) {
            if (!file.mimetype.startsWith("image/")) return res.status(400).json({ error: "Upload image only" });

            if (file.size > 2 * 1024 * 1024) return res.status(400).json({ error: `Your image size too large (max 2MB)` });
        };
    };

    const session = await mongoose.startSession();
    session.startTransaction();

    let uploadFiles = [];
    try {

        // create empty post
        const [uploadPost] = await postSchema.create([{ author: req.user._id, content: cleanContent || null}], { session });

        // update userSchema
        await userSchema.findByIdAndUpdate(req.user._id,
            { $push: { posts: uploadPost._id } },
            { session }
        );

        if (!files || files.length === 0) {
            await session.commitTransaction();
            return res.sendStatus(200)
        };

        // upload to google drive
        const newFiles = await Promise.all(files.map(async (file) => { 
            // getting readable file from buffer file
            const uploadBuffer = new stream.PassThrough();
            uploadBuffer.end(file.buffer);

            try {
                const uploadFile = await GDPostConfig.files.create({
                    requestBody: {
                        name: file.originalname,
                        parents : [process.env.FOLDER_POST_ID]
                    },
                    media: {
                        mimeType: file.mimetype,
                        body: uploadBuffer,
                    },
                    fields: "id, size, name, mimeType",
                });

                uploadFiles.push(uploadFile.data.id);

                await GDPostConfig.permissions.create({
                    fileId: uploadFile.data.id,
                    requestBody: {
                        role: "reader",
                        type: "anyone",
                    },
                });

                const [savedFile] = await filePostSchema.create(
                    [{
                        author: req.user._id,
                        fileId: uploadFile.data.id,
                        fileName: uploadFile.data.name,
                        fileType: uploadFile.data.mimeType,
                        fileSize: uploadFile.data.size,
                        post: uploadPost._id,
                }], { session });

                return savedFile;

            } catch (e) {
                throw new Error(`Failed upload file to google drive:`, e);
            };

        }));

        // update post
        await postSchema.findByIdAndUpdate(uploadPost._id,
            { $set: { files: newFiles.map(f => f._id) } },
            { session }
        );
        
        await session.commitTransaction();

        return res.sendStatus(200);


    } catch (e) {
        await session.abortTransaction();
        for (const id of uploadFiles) {
            try {
                await GDPostConfig.files.delete({ fileId: id });
            } catch {
                console.warn(`⚠️ Failed to delete file ${id} from Drive during rollback`);
            }
        };
        console.log(e)
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    } finally {
        session.endSession();
    };
});



// update post
router.put("/update-post/:id", JWTVerification, postRateLimiter, async (req, res) => {
    const { content } = req.body;
    const postId = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(postId)) {
        return res.status(400).json({ error: "Invalid post ID format" });
    };

    // content and file validation
    if (content && content.length > 300) return res.status(400).json({ error: "Content length too long (max 300 characters" });

    const cleanContent = sanitizeHtml(content || "", { allowedTags: [], allowedAttributes: {} }).trim();

    try {
        // available post validation
        const post = await postSchema.findById(postId).populate("files");
        if (!post) {
            return res.status(404).json({ error: "Post not found" });
        }
        if (String(post.author) !== String(req.user._id)) {
            return res.status(403).json({ error: "You are not allowed to update this post" });
        }

        // editable validation
        if (post.editExpAt < Date.now()) {
            return res.status(400).json({ error: "Post can only be updated within 10 minutes after creation" });
        }


        // content update
        if (content) {
            post.content = cleanContent || null;
        }

        // save the change
        await post.save();

        return res.sendStatus(200);

    } catch (e) {
        console.error(e);
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    }
});


// Delete post
router.delete("/delete-post/:id", JWTVerification, postRateLimiter, async (req, res) => {
    const postId = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(postId)) {
        return res.status(400).json({ message: "Invalid post ID format" });
    };

    try {
        // validation post
        const post = await postSchema.findById(postId).populate("files").populate("author");

        if (!post) {
            return res.status(404).json({ message: "Post not found" });
        };

        if (String(post.author._id) !== String(req.user._id)) {
            return res.status(403).json({ message: "You are not allowed to delete this post" });
        };

        // delete all related comments and reply comments
        const comments = await commentSchema.find({ post: postId }).populate("file");

         // 3️⃣ Hapus semua comment + reply + file secara paralel
        await Promise.all(comments.map((comment) => limit(async() => {
            // Ambil semua reply-comment milik comment ini
            const replies = await replyCommentSchema.find({ comment: comment._id }).populate("file");
            const notifications = await notificationSchema.find({ comment: comment._id });

            // delete notification comment
            await Promise.all(notifications.map(notification => limit(async () => {
                await notificationSchema.findByIdAndDelete(notification._id);
            })));

            // Hapus file di setiap reply
            await Promise.all(replies.map((reply) => limit(async() => {
                if (reply.file?._id) {
                    try {
                        await GDReplyCommentConfig.files.delete({ fileId: reply.file.fileId });
                    } catch (err) {
                        console.warn(`⚠️ Failed to delete reply file ${reply.file.fileId}:`, err.message);
                    }
                    await fileReplyCommentSchema.findByIdAndDelete(reply.file._id);
                }
                await replyCommentSchema.findByIdAndDelete(reply._id);
            })));

            // Hapus file dari comment
            if (comment.file?._id) {
                try {
                    await GDCommentConfig.files.delete({ fileId: comment.file.fileId });
                } catch (err) {
                    console.warn(`⚠️ Failed to delete comment file ${comment.file.fileId}:`, err.message);
                }
                await fileCommentSchema.findByIdAndDelete(comment.file._id);
            }

            // Hapus comment itu sendiri
            await commentSchema.findByIdAndDelete(comment._id);
        })));



        // delete post from mongodb and google drive
        if (post.files?.length > 0) {
            await Promise.all(post.files.map((file) => limit(async() => {
                try {
                    await GDPostConfig.files.delete({ fileId: file.fileId });
                } catch (err) {
                    console.warn(`⚠️ Failed to delete post file ${file.fileId}:`, err.message);
                }
                await filePostSchema.findByIdAndDelete(file._id);
            })));
        };


        // delete post
        await postSchema.findByIdAndDelete(post._id);

        // update userSchema
        await userSchema.findByIdAndUpdate(req.user._id, {
            $pull: { posts: post._id }
        });

        return res.sendStatus(200)

    } catch (e) {
        console.error(e);
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    };
});


// get post feed
router.get("/post-feed", JWTVerification, getRateLimiter, async (req, res) => { 
    try {
        const posts = await postSchema.find()
            .sort({ createdAt: -1 })
            .populate({
                path: "files",
                select : "author fileId _id"
            })
            .populate({
                path: "author",
                select : "username avatar _id followers"
            })


        return res.status(200).json({ posts });

    } catch (e) {
        console.error(e);
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    };
});

// get detail post
router.get("/post-detail/:postId", JWTVerification, getRateLimiter, async (req, res) => {
    const postId = req.params.postId;
    try {
        const post = await postSchema.findById(postId)
            .populate({
                path: "author",
                select : "username avatar _id"
            })
            .populate({
                path: "files",
                select : "author fileId _id"
            })
            .populate({
                path: "comments",
                options: { sort: { createdAt: -1 } },
                select : "_id author content likes file replyComments",
                populate: [
                    {
                        path: "file",
                        select : "author fileId _id"
                    },
                    {
                        path: "author",
                        select : "username avatar _id"
                    },
                    {
                        path: "replyComments",
                        select : "_id author content likes file",
                    }]
        });

        if (!post) return res.status(404).json({ message: "Post not found" });

        return res.status(200).json({ post });

    } catch (e) {
        console.log(e);
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    }
});


module.exports = router;