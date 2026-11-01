import crypto from "crypto";
import fs from "fs/promises";
import path from "path";
import File from "../models/file.model.js";
import AppError from "../utils/AppError.js";
import securityEventService from "./securityEvent.service.js";

const UPLOAD_DIRECTORY = path.resolve(
    process.cwd(),
    "uploads"
);

// check wheather a stored file has beed modified
const checkFileItegrity = async (fileId, userId) => {

    // find the file and enforce ownership

    const file = await File.findOne({
        _id: fileId, userId,
    });

    if (!file) {
        throw new AppError(
            "file not found or access denied.", 404
        );
    }

    // Only safe files can undergo integrity verification.
if (file.status !== "safe") {
    throw new AppError(
        "Integrity check is only available for safe files.",
        409
    );
}

    // build the physical path from server controlled file name
    const filePath = path.join(
        UPLOAD_DIRECTORY,
        file.storedName
    );

    let fileBuffer;

    try {
        fileBuffer = await fs.readFile(filePath);
    } catch (error) {

        // file exists in MongoDB  not on disk
        file.integrityStatus = "unavailable";
        await file.save();

        throw new AppError(
            "Physical file is unavailable.", 404
        );
    }

    // calculate the current SHA hash
    const currentHash = crypto
        .createHash("sha256")
        .update(fileBuffer)
        .digest("hex");

    // hash current hash with trusted baseline
    const isIntact = currentHash === file.hash;

    file.integrityStatus = isIntact
        ? "intact"
        : "modified";

    await file.save();

    if (!isIntact) {
        await securityEventService.createSecurityEvent({
            userId, fileId: file._id,
            eventType: "integrity_violation",
            previousHash: file.hash, currentHash,
            riskScore: 10,
            reason: "your file contents differ from the trusted baseline.",
            metadata:{
                originalName: file.originalName,
            },
        });
    }

    return {
        fileId: file._id,
        originalName: file.originalName,
        expectedHash: file.hash,
        currentHash,
        integrityStatus: file.integrityStatus,
    };

};

export default {
    checkFileItegrity,
};

