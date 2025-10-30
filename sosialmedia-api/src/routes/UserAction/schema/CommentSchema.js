const mongoose = require("mongoose");

const schema = new mongoose.Schema({
    post: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "post",
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
        ref : 'filecomment'
    },
    replyComments: [{
        type: mongoose.Schema.Types.ObjectId,
        ref : 'replycomment'
    }]
    },
    { timestamps: true }
);


const commentSchema = mongoose.model("comment", schema);

module.exports = commentSchema;
