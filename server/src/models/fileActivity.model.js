import mongoose from "mongoose";

const fileActivitySchema = new mongoose.Schema({
    userId:{
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
        index: true,
    },

    fileId:{
        type: mongoose.Schema.Types.ObjectId,
        ref: "File",
        required: true,
        index: true,
    },

    activityType:{
        type: String,
        enum: [
            "created",
            "modified",
            "renamed",
            "deleted",
            "recovered",
            "recovery_failed",
        ],
        required: true,
        index: true,  
    },

    previousName: {
        type: String,
        default: null,
        trim: true,
    },

    currentName: {
        type: String,
        default: null,
        trim: true,
    },

    previousExtension:{
        type: String,
        default: null,
        trim: true,
    },

    currentExtension:{
        type: String,
        default: null,
        trim: true,
    },
},
{
    timestamps: true,
}
);
fileActivitySchema.index({ userId: 1, createdAt: -1 });
const FileActivity = mongoose.model(
    "FileActivity",
    fileActivitySchema
);


export default FileActivity;