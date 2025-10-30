const mongoose = require("mongoose");

const schema = new mongoose.Schema({
    post: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "post",
    },
    // penerima
    recipient: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'user',
        required: true,
    },
    // pengirim
    sender: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "user",
        required: true
    },
    type: {
        type: String,
        enum: ["like", "comment", "follow", "replycomment"],
        required: true,
    },
    comment: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "comment", 
    },
    replyComment: {
        type: mongoose.Schema.Types.ObjectId,
        ref : "replycomment"
    },
    message: {
        type: String, 
        trim: true,
        required: true
    },
    isRead: {
        type: Boolean,
        default: false,
    },

}, { timestamps: true });

const notificationSchema = mongoose.model("notification", schema);

module.exports = notificationSchema;