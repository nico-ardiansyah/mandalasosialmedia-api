const mongoose = require("mongoose");

const schema = new mongoose.Schema({
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "user", 
        required: true,
    },
    comment: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "comment",
        required : true
    },
    fileId: {
        type: String,
        required : true,
    },
    fileName: {
        type: String,
        required: true,
        trim: true,
    },
    fileType: {
        type: String, 
        required: true,
    },
    fileSize: {
        type: Number, 
        required: true,
    },
    },
    { timestamps: true }
    );

const fileCommentSchema = mongoose.model("filecomment", schema);

module.exports = fileCommentSchema;
