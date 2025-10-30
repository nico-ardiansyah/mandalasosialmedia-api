const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const sgMail = require("@sendgrid/mail");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const stream = require("stream");
const { rateLimit, ipKeyGenerator } = require("express-rate-limit");
const sanitizeHtml = require("sanitize-html");
const mongoose = require("mongoose");


// req post limiter
const postRateLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 15,
    message: { message: "Too many request, please try again later" },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.user?._id || ipKeyGenerator,
});

// req get limiter
const getRateLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    message: { message: "Too many request, please try again later" },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.user?._id || ipKeyGenerator,
});


// sendgrid and nodemailer config
sgMail.setApiKey(process.env.SENDGRID_API_KEY);
const ms = require("../../../Nodemailer/NodemailerMessage");

// localstorage for image
const upload = multer({ storage : multer.memoryStorage() });

// jwt validation
const JWTVerification = require("../../../Services/JWT/JWTVerification");

// schema
const userSchema = require("../schema/UserSchema");
const fileAvatarSchema = require("../schema/FileAvatarSchema");

// validation joi
const signUpValidationJoi = require("../ValidationJoi/SignUpValidationJoi");
const signInValidationJoi = require("../ValidationJoi/SignInValidationJoi");
const passwordValidation = require("../ValidationJoi/PasswordValidationJoi");
const emailValidation = require("../ValidationJoi/EmailValidationJoi");

// Google drive config
const GDAvatarConfig = require("../GoogleDriveConfig/GDAvatarConfig");

// signup
router.post("/auth/signup", postRateLimiter, async (req, res) => {
    const { username, email, password, confirmPassword } = req.body;
    const code = crypto.randomBytes(3).toString('hex');

    const cleanUsername = sanitizeHtml(username || "", { allowedTags: [], allowedAttributes: {} }).trim();
    const cleanEmail = sanitizeHtml(email || "", { allowedTags: [], allowedAttributes: {} }).trim().toLowerCase();

    // validation joi
    const { value, error } = signUpValidationJoi.validate({ username: cleanUsername, email: cleanEmail, password, confirmPassword }, { stripUnknown: true });
    
    if (error) {
        const errors = {};
        error.details.forEach(e => {
            const field = e.path[0];
            errors[field] = e.message
        })

        return res.status(400).json(errors);
    }

    const { username: safeUsername, email: safeEmail, password: safePassword } = value;

    try {
        
        // find data from db
        const [findUser, findEmail] = await Promise.all([
            userSchema.findOne({ username: safeUsername }),
            userSchema.findOne({ email: safeEmail })
        ]);


        // data from db validation
        if (findUser && findUser.isVerified) return res.status(409).json({ username: "Username has been taken" });
        if (findEmail && findEmail.isVerified) return res.status(409).json({ email: "Email has been taken" });
        if (findUser?.resendAvailableAt > Date.now() || findEmail?.resendAvailableAt > Date.now()) {
            const waitTime = Math.ceil((user.resendAvailableAt - Date.now()) / 1000);
            return res.status(429).json({ message: `Please wait ${waitTime} seconds before requesting again` });
        };
        
        // hashed password
        const hashPassword = await bcrypt.hash(safePassword, 5);

        // case 1 ==== user = false, email = true + unverif
        if (!findUser && findEmail && !findEmail.isVerified && findEmail.expCode > Date.now()) {
            try {
                await sgMail.send(ms(safeEmail, code, "OTP"));
            } catch (e) {
                console.log(e)
                return res.status(500).json({ message: 'Failed to send code' });
            };

            await userSchema.updateOne(
                { _id: findEmail._id },
                {
                    $set: {
                        username : safeUsername,
                        email : safeEmail,
                        password: hashPassword,
                        code,
                        resendAvailableAt: new Date(Date.now() + 2 * 60 * 1000),
                        expCode : new Date(Date.now() + 10 * 60 * 1000)
                    }
                }
            );

            return res.sendStatus(201);
        };


        // case 2 ==== user = true + unverif, email = false
        if (findUser && !findUser.isVerified && !findEmail && findUser.expCode > Date.now()) {
            try {
                await sgMail.send(ms(safeEmail, code, "OTP"));
            } catch (e) {
                console.log(e)
                return res.status(500).json({ message: 'Failed to send code' });
            };

            await userSchema.updateOne(
                { _id: findUser._id },
                {
                    $set: {
                        username : safeUsername,
                        email : safeEmail,
                        password: hashPassword,
                        code,
                        resendAvailableAt: new Date(Date.now() + 2 * 60 * 1000),
                        expCode : new Date(Date.now() + 10 * 60 * 1000)
                    }
                }
            );

            return res.sendStatus(201);
        };

        // case 3 ==== user = false, email = false
        if (!findUser && !findEmail) {
            try {
                await sgMail.send(ms(safeEmail, code, "OTP"));
            } catch (e) {
                console.log(e)
                return res.status(500).json({ message: 'Failed to send code' });
            };

            await userSchema.create({
                username : safeUsername,
                email : safeEmail,
                password: hashPassword,
                code,
            });

            return res.sendStatus(201)
        };


    } catch (e) {
        console.error(e);
        res.status(500).json({ message: "Something went wrong, please try again later" });
    }
});

// signup verification
router.post("/signup/verify", postRateLimiter, async (req, res) => {
    const { email, code } = req.body;

    const cleanEmail = sanitizeHtml(email || "", { allowedTags: [], allowedAttributes: {} }).trim().toLowerCase();
    const cleanCode = sanitizeHtml(code || "", { allowedTags: [], allowedAttributes: {} }).trim();

    try {
        const user = await userSchema.findOne({ email : cleanEmail });

        // user data validation
        if (!user) return res.status(404).json({ message: "User not found" });
        if (user && user.isVerified) return res.status(409).json({ message: "User already verified" });
        if (user.expCode < Date.now()) return res.status(410).json({ code: "Code has expired" });
        if (user.code !== cleanCode) return res.status(400).json({ code: "Invalid code" });

        // uppdate user data in db
        await userSchema.updateOne(
            { _id: user._id },
            {
                $set: {
                    isVerified: true,
                    code: null,
                    expCode: null,
                    resendAvailableAt : null,
                }
            }
        );

        return res.sendStatus(200)

    } catch (e) {
        console.error(e);
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    };
});


// resnd-code
router.post("/resend-code", postRateLimiter, async (req, res) => {
    const { email } = req.body;
    const code = crypto.randomBytes(3).toString('hex');
    const cleanEmail = sanitizeHtml(email || "", { allowedTags: [], allowedAttributes: {} }).trim().toLowerCase();

    try {
        const user = await userSchema.findOne({ email : cleanEmail });

        // validation
        if (!user) return res.status(404).json({ message: "User not found" });

        // cooldown
        if (user.resendAvailableAt > Date.now()) {
            const waitTime = Math.ceil((user.resendAvailableAt - Date.now()) / 1000);
            return res.status(429).json({ message: `Please wait ${waitTime} seconds before requesting again` });
        };

        // send otp
        try {
            await sgMail.send(ms(safeEmail, code, "OTP"));
        } catch (e) {
            console.log(e);
            return res.status(500).json({ message: "Failed to send code" });
        }

        // update new code + exp code + cooldown
        await userSchema.updateOne(
            { _id: user._id },
            {
                $set: {
                    code,
                    expCode: Date.now() + 1000 * 60 * 10, 
                    resendAvailableAt: Date.now() + 1000 * 60 * 2
                }
            }
        );

        return res.sendStatus(200);

    } catch (e) {
        console.error(e);
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    }
});


// request forgot password
router.post("/forgot-password", postRateLimiter, async (req, res) => {
    const { email } = req.body;
    const code = crypto.randomBytes(3).toString("hex");

    const cleanEmail = sanitizeHtml(email || "", { allowedTags: [], allowedAttributes: {} }).trim().toLowerCase();
    
    // validation joi
    const { value, error } = emailValidation.validate({ email : cleanEmail }, { stripUnknown: true } );
    if (error) {
        const errors = {};
        error.details.forEach(e => {
            const field = e.path[0];
            errors[field] = e.message
        })

        return res.status(400).json(errors);
    };

    const { email: safeEmail } = value;

    try {


        const user = await userSchema.findOne({ email : safeEmail });

        // validation
        if (!user) return res.status(404).json({ email: "Email not found" });
        if (user && !user.isVerified) return res.status(400).json({ email: "Your account is not verified" });
        if (user.resendAvailableAt > Date.now()) {
            const waitTime = Math.ceil((user.resendAvailableAt - Date.now()) / 1000);
            return res.status(429).json({ message: `Please wait ${waitTime} seconds before requesting again` });
        };


        // send otp
        try {
            await sgMail.send(ms(safeEmail, code, "Reset Password"));
            
        } catch (e) {
            console.log(e)
            return res.status(500).json({ message: 'Failed to send code' });
        };
        
        // update db
        await userSchema.updateOne(
            { _id: user._id },
            {
                $set: {
                    code,
                    codeExp: Date.now() + 1000 * 60 * 10,
                    resendAvailableAt : Date.now() + 2 * 60 * 1000,
                }   
            }
        );
        
        return res.sendStatus(200)

    } catch (e) {
        console.error(e);
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    }
});


router.post("/reset-password", postRateLimiter, async (req, res) => {
    const { email, code, password, confirmPassword } = req.body;

    const cleanEmail = sanitizeHtml(email || "", { allowedTags: [], allowedAttributes: {} }).trim().toLowerCase();

    // joi validation
    const { error } = passwordValidation.validate({ password, confirmPassword }, { stripUnknown : true });
    if (error) {
        const errors = {};
        error.details.forEach(e => {
            const field = e.path[0];
            errors[field] = e.message
        })

        return res.status(400).json(errors);
    }

    const { password: safePassword } = value;

    try {

        const user = await userSchema.findOne({ email : cleanEmail });

        // data validation
        if (!user) return res.status(404).json({ email: "Email not found" });
        if (user.code !== code) return res.status(400).json({ code: "Invalid code" });
        if (user.codeExp < Date.now()) return res.status(410).json({ code: "Code has expired" });

        const hashPassword = await bcrypt.hash(safePassword, 5);

        await userSchema.updateOne(
            { _id: user._id },
            {
                $set:
                {
                    password: hashPassword,
                    code: null,
                    codeExp: null,
                    resendAvailableAt : null
                },
            });
        
        return res.sendStatus(200);


    } catch (e) {
        console.error(e);
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    }
});



// signin
router.post("/auth/signin", getRateLimiter, async (req, res) => {
    const { email, password } = req.body;

    const cleanEmail = sanitizeHtml(email || "", { allowedTags: [], allowedAttributes: {} }).trim().toLowerCase();

    // joi validation
    const {value, error } = signInValidationJoi.validate({ email : cleanEmail, password }, {stripUnknown: true});
    if (error) {
        const errors = {};
        error.details.forEach(e => {
            const field = e.path[0];
            errors[field] = e.message
        })

        return res.status(400).json(errors);
    };

    const { email: safeEmail, password: safePassword } = value;

    try {

        const findEmail = await userSchema.findOne({ email : safeEmail });

        // email data validation
        if (!findEmail) return res.status(404).json({ email: "Email not found" });
        if (findEmail && !findEmail.isVerified) return res.status(403).json({ email: "Your account is not verified" });
        
        // password validation
        const isPasswordValid = await bcrypt.compare(safePassword, findEmail.password);
        if (!isPasswordValid) return res.status(401).json({ password: "Password is incorrect" });


        // jwt
        const jwtToken = jwt.sign({ _id: findEmail._id, username: findEmail.username }, process.env.JWT_SECRETKEY, { expiresIn: '1h' });
        
        
        return res.cookie("access_token", jwtToken, {
            httpOnly: true,
            secure: true,
            sameSite: "None",
            path: "/",
            maxAge: 3600000
        }).sendStatus(200);
        
    } catch (e) {
        console.log(e)
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    };
});


// get profile
router.get("/:userId/profile", JWTVerification, getRateLimiter, async (req, res) => {
    const userId = req.params.userId;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({ message: "Invalid user ID format" });
    };

    try {
        const user = await userSchema.findById(userId)
            .select("username avatar bio name notifications posts followers following")
            .populate({
                path: "posts",
                options: { sort: { createdAt: -1 } },
                populate: [{
                    path: "author",
                    select : ("_id username avatar")
                }, {
                    path: "files",
                    select : ("_id fileId")
                }]
            })
            .populate({
                path: "avatar",
                select : ("_id fileId")
            })
            .populate({
                path: "notifications",
                options: { sort: { createdAt: -1 }, limit: 5 },
                populate: [
                    {
                        path: "post",
                        select : ("_id content author")
                    },
                    {
                        path: "recipient",
                        select : ("_id username")
                    },
                    {
                        path: "sender",
                        select : ("_id username avatar")
                    },
                    {
                        path: "comment",
                        populate: "post",
                        select : ("_id author post")
                    },
                    { 
                        path: "replyComment",
                        select : ("_id author")
                    }
                ]
        }).populate({
            path: "followers",
            populate: {
                path: "avatar",
                select : ("_id fileId")
            },
            select : ("_id avatar username")
        }).populate({
            path: "following",
            populate: {
                path: "avatar",
                select : ("_id fileId")
            },
            select : ("_id avatar username")
        })

        if (!user) return res.status(404).json({ message: "User not found" });
        
        return res.json({user});

    } catch (e) {
        console.error(e)
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    };
});


// changed avatar
router.post("/upload-avatar", JWTVerification, postRateLimiter, upload.single("file"), async (req, res) => { 
    const file = req.file;
    if (!file) return res.status(400).json({ error: "Choose your photo first" });

    if (!file.mimetype.startsWith("image/")) {
        return res.status(400).json({ error: "Avatar can only file image" })
    };

    if (file.size > 2 * 1024 * 1024) {
        return res.status(400).json({ error: `Your file size too large (max 2MB)` });
    };

    try {
        const user = await userSchema.findById(req.user._id).populate("avatar");
        if (!user) return res.status(404).json({ message: "User not found" });

        // getting readable file from buffer file
        const bufferStream = new stream.PassThrough();
        bufferStream.end(file.buffer);

        // upload file
        let uploadFile;
        try {
            uploadFile = await GDAvatarConfig.files.create({
                requestBody: {
                    name: file.originalname,
                    parents : [process.env.FOLDER_AVATAR_ID]
                },
                media: {
                    mimeType: file.mimetype,
                    body: bufferStream,
                },
                fields: "id, size, name, mimeType",
            });

            // give permission file
            await GDAvatarConfig.permissions.create({
                fileId: uploadFile.data.id,
                requestBody: {
                    role: "reader",
                    type: "anyone",
                },
            });

        } catch (e) {
            console.error("Google Drive upload error:", e.message);
            return res.status(500).json({ message: "Failed to upload avatar" });
        };

        // delete file
        if (user.avatar?.fileId && user.avatar.fileId != "1A8JIDhPsQ6s1zRAYjFl_qXq0qUBE5Ah6") {
            try { 
                await GDAvatarConfig.files.delete({ fileId : user.avatar.fileId})
            } catch (e) { 
                console.error("Delete file error::", e.message);
            };
        };

        // upload to db
        const uploadAvatar = await fileAvatarSchema.create({
            author: req.user._id,
            fileId: uploadFile.data.id,
            fileName: uploadFile.data.name,
            fileType: uploadFile.data.mimeType,
            fileSize: uploadFile.data.size,
        });

        await userSchema.findByIdAndUpdate(req.user._id, {
            $set: { avatar: { _id: uploadAvatar._id, fileId: uploadAvatar.fileId } }
        });

        return res.sendStatus(201);


    } catch (e) {
        console.log(e)
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    };
});

// delete avatar
router.delete("/delete-avatar", JWTVerification, postRateLimiter, async (req, res) => {
    const default_avatar = "1A8JIDhPsQ6s1zRAYjFl_qXq0qUBE5Ah6" 

    try {
        const user = await userSchema.findById(req.user._id).populate("avatar");
        if (!user) return res.status(404).json({ error: "User not found" });

        if (!user.avatar || !user.avatar.fileId) {
            return res.status(400).json({ error: "No avatar to delete" });
        };

        // validate default file
        if (user.avatar.fileId === default_avatar) return res.status(400).json({ error: "No avatar to delete" });

        // delete file from google drive
        try {
            await GDAvatarConfig.files.delete({ fileId: user.avatar.fileId });
        } catch (e) {
            console.log("Failed delete file from Google Drive:", e)
            return res.status(500).json({ message: "Failed to delete avatar" });
        };

        // delete file from db
        await fileAvatarSchema.findByIdAndDelete(user.avatar._id);

        await userSchema.findByIdAndUpdate(req.user._id, {
            $set: { avatar: { fileId: default_avatar } }
        });

        return res.sendStatus(204);

    } catch (e) {
        console.log(e)
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    };
});


// change name
router.post("/change-name", JWTVerification, postRateLimiter, async (req, res) => { 
    const name = req.body.name;
    if (!name || !name.trim()) return res.status(400).json({ error: "Name is required" });
    if (name.length > 50) return res.status(400).json({ error: "Name length too long (max 50 characters)" });

    const cleanInput = sanitizeHtml(name || "", { allowedTags: [], allowedAttributes: {} }).trim();

    const cleanName = cleanInput.replace(/\s+/g, " ");

    try { 
        const user = await userSchema.findByIdAndUpdate(req.user._id,
            { $set: { name: cleanName } },
            {new : true}
        );

        if (!user) return res.status(404).json({ message: "User not found" });


        return res.sendStatus(200);

    } catch (e) { 
        console.log(e)
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    };
});

// delete name
router.delete("/delete-name", JWTVerification, postRateLimiter, async (req, res) => { 
    try { 
        const user = await userSchema.findByIdAndUpdate(
            req.user._id,
            { $set: { name: null } },
            { new: true }
        );

        if (!user) return res.status(404).json({ message: "User not found" });

        return res.sendStatus(200);

    } catch (e) { 
        console.log(e)
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    };
});

// router change biography
router.post("/change-bio", JWTVerification, postRateLimiter, async (req, res) => { 
    const bio = req.body.bio;
    if (!bio || !bio.trim()) return res.status(400).json({ error: "Bio is required" });
    if (bio.length > 160) return res.status(400).json({ error: "Bio length too long (max 160 characters)" });

    const cleanInput = sanitizeHtml(bio || "", { allowedTags: [], allowedAttributes: {} }).trim();

    try { 
        const user = await userSchema.findByIdAndUpdate(req.user._id,
            { $set: { bio : cleanInput } },
            {new : true}
        );
        
        if (!user) return res.status(404).json({ message: "User not found" });

        return res.sendStatus(200);

    } catch (e) { 
        console.log(e)
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    };
});

// delete bio
router.delete("/delete-bio", JWTVerification, postRateLimiter, async (req, res) => { 
    try { 
        const user = await userSchema.findByIdAndUpdate(
            req.user._id,
            { $set: { bio: null } },
            { new: true }
        );
        
        if (!user) return res.status(404).json({ message: "User not found" });

        return res.sendStatus(200)

    } catch (e) { 
        console.log(e)
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    };
});

// logout endpoint
router.post("/auth/sign-out", postRateLimiter, async(req, res) => {
    try { 
        res.clearCookie("access_token", {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite : "strict",
            path: "/",
        });

        return res.sendStatus(200)
    } catch (e) { 
        console.log(e)
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    };
});

// get user info from jwt
router.get('/user-info', JWTVerification, getRateLimiter, async (req, res) => { 
    try { 
        const id = req.user._id;
        return res.json({ id });
        
    } catch (e) { 
        console.log(e)
        return res.status(500).json({ message: "Something went wrong, please try again later" });
    };
});



module.exports = router;
