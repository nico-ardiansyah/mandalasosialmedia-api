const mongoose = require("mongoose");

const schema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        trim: true,
        lowercase: true,
        unique: true,
        minlength: 5,
        maxlength : 30
    },
    password: {
        type: String,
        required: true,
        trim: true,
    },
    email: {
        type: String,
        required: true,
        lowercase: true,
        match: [/^\S+@\S+\.\S+$/, "Invalid email format"],
        trim: true,
        unique: true
    },
    isVerified: {
        type: Boolean,
        default: false,
    },
    code: {
        type: String,
        required: true,
    },
    expCode: {
        type: Date,
        default: new Date(Date.now() + 10 * 60 * 1000)
    },
    bio: {
        type: String,
        maxlength : 160
    },
    name: {
        type: String,
        maxlength : 50
    },
    notifications: [{
        type: mongoose.Types.ObjectId,
        ref: "notification"
    }],
    posts: [{
        type: mongoose.Types.ObjectId,
        ref: 'post'
    }],
    resendAvailableAt: {
        type: Date,
        default: new Date(Date.now() + 2 * 60 * 1000),
    },
    avatar: {
        _id: {
            type: mongoose.Types.ObjectId,
            ref: 'fileavatar'
        },
        fileId: {
            type: String,
            default: "1A8JIDhPsQ6s1zRAYjFl_qXq0qUBE5Ah6"
        },
    },
    followers: [{
        type: mongoose.Types.ObjectId,
        ref: 'user'
    }],
    following: [{
        type: mongoose.Types.ObjectId,
        ref: 'user'
    }],
}, {timestamps : true});

const userSchema = mongoose.model('user', schema);
module.exports = userSchema;