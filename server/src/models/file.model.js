// import { hash } from "bcryptjs"; wrong import use in future
import mongoose from "mongoose";
// import { maxLength, string } from "zod";  wrong import use in future
const fileSchema = new mongoose.Schema(
  {
    // identify the user who owns the file
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },

    // preserve the original filename for user display
    originalName: {
      type: String,
      required: true,
      trim: true,
      maxLength: 255,
    },

    // store the file using a controlled internal name
    storedName: {
      type: String,
      required: true,
      unique: true,
    },

    // identify where the file is physically stored
    storagePath: {
      type: String,
      required: true,
    },

    //file MIME type
    mimeType: {
      type: String,
      required: true,
    },

    // store  file size in bytes
    size: {
      type: Number,
      required: true,
      min: 0,
    },

    //store cryptographic file fingerprint sha 256
    hash: {
      type: String,
      required: true,
      index: true,
    },

    // Server-controlled filename of the trusted backup
    backupStoredName: {
      type: String,
      required: false,
      default: null,
    },

    // Physical path of the trusted backup
    backupStoragePath: {
      type: String,
      required: false,
      default: null,
    },

    // SHA-256 fingerprint of the trusted backup
    backupHash: {
      type: String,
      required: false,
      default: null,
      index: true,
    },

    // track the security state of the file
    status: {
      type: String,
      enum: ["pending", "safe", "suspicious", "infected", "quarantined"],
      default: "pending",
      required: true,
      index: true,
    },

    //integrity status
    integrityStatus: {
      type: String,
      enum: ["intact", "modified", "unavailable"],
      default: "intact",
      required: true,
      index: true,
    },
  },
  {
    timestamps: true,
  },
);


fileSchema.index(
    { backupStoredName: 1 },
    {
        unique: true,
        partialFilterExpression: {
            backupStoredName: { $type: "string" },
        },
    }
);

const File = mongoose.model("File", fileSchema);

export default File;
