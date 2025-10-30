const mongoose = require("mongoose");

const schema = new mongoose.Schema({
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "user", 
        required: true,
    },
    post: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "post",
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

const filePostSchema = mongoose.model("filepost", schema);

module.exports = filePostSchema;
