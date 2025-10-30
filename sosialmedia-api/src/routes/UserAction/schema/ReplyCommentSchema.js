const mongoose = require("mongoose");

const schema = new mongoose.Schema({
    comment: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "comment",
        required: true, 
    },
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "user",
        required: true, 
    },
    content: {
        type: String,
        maxlength: 500, 
    },
    likes: [
        {
        type: mongoose.Schema.Types.ObjectId,
        ref: "user", 
        },
    ],
    file: {
        type: mongoose.Schema.Types.ObjectId,
        ref : 'filereplycomment'
    }
    },
    { timestamps: true }
);


const replyCommentSchema = mongoose.model("replycomment", schema);

module.exports = replyCommentSchema;
