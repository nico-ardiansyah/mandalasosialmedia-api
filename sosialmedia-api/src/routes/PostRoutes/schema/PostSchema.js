const mongoose = require("mongoose");

const schema = new mongoose.Schema({
    author: {
        type: mongoose.Types.ObjectId,
        ref: "user",
        required : true,
    },
    content: {
        type: String,
        maxlength : 300,
    },
    files: [{
        type: mongoose.Types.ObjectId,
        ref : 'filepost'
    }],
    likes: [{
        type: mongoose.Types.ObjectId,
        ref : 'user'
    }],
    comments: [{
        type: mongoose.Types.ObjectId,
        ref : 'comment'
    }],
    editExpAt: {
        type: Date,
        default : () => new Date(Date.now() + 10 * 60 * 1000),
    }
}, {timestamps : true});

const postSchema = mongoose.model("post", schema);

module.exports = postSchema;