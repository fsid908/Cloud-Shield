import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import File from "../models/file.model.js";
import AppError from "../utils/AppError.js";
import storagePath from "../utils/storagePath.js";
import securityEventService from "./securityEvent.service.js";

const UPLOAD_DIRECTORY = path.resolve(
    process.cwd(),
    "uploads"
);

const BACKUP_DIRECTORY = path.resolve(
    UPLOAD_DIRECTORY,
    "backups"
);

const QUARANTINE_DIRECTORY = path.resolve(
    UPLOAD_DIRECTORY,
    "quarantine"
);

const ALLOWED_RISK_LEVELS = ["high", "critical"];

/**
 * Checks whether a file exists without hiding unexpected filesystem errors.
 */
const fileExists = async (filePath) => {
    try {
        await fs.access(filePath);
        return true;
    } catch (error) {
        if (error.code === "ENOENT") {
            return false;
        }

        throw error;
    }
};

// Moves one eligible file into quarantine.
// The trusted backup is deliberately left untouched.

const containFile = async ({
    userId,
    fileId,
    riskScore,
    riskLevel,
    episodeId,
    reason,
}) => {
    if (!userId || !fileId) {
        throw new AppError(
            "User ID and file ID are required.",
            400
        );
    }

    if (
        !Number.isFinite(riskScore) ||
        riskScore < 0 ||
        riskScore > 100
    ) {
        throw new AppError(
            "Risk score must be between 0 and 100.",
            400
        );
    }

    if (!ALLOWED_RISK_LEVELS.includes(riskLevel)) {
        throw new AppError(
            "Containment is only allowed for high or critical risk.",
            403
        );
    }

    const file = await File.findOne({
        _id: fileId,
        userId,
    });

    if (!file) {
        throw new AppError(
            "File not found or access denied.",
            404
        );
    }

    if (file.status === "quarantined") {
        return {
            fileId: String(file._id),
            status: "already_quarantined",
        };
    }

    if (file.status !== "safe") {
        return {
            fileId: String(file._id),
            status: "skipped",
            reason: "File is not in a safe state.",
        };
    }

    // Only server-controlled filenames are used to construct paths.
    const sourcePath = storagePath.resolveStoragePath(
        UPLOAD_DIRECTORY,
        file.storedName
    );

    if (!(await fileExists(sourcePath))) {
        return {
            fileId: String(file._id),
            status: "skipped",
            reason: "Original file is missing.",
        };
    }

    // Preserve the backup. Never move it into quarantine.
    let backupAvailable = false;

    if (file.backupStoredName && file.backupHash) {
        const backupPath = storagePath.resolveStoragePath(
            BACKUP_DIRECTORY,
            file.backupStoredName
        );

        backupAvailable = await fileExists(backupPath);
    }

    await fs.mkdir(QUARANTINE_DIRECTORY, {
        recursive: true,
    });

    const quarantinedStoredName =
        `${crypto.randomUUID()}${path.extname(file.storedName)}`;

    const quarantinedPath = storagePath.resolveStoragePath(
        QUARANTINE_DIRECTORY,
        quarantinedStoredName
    );

    const previousStoredName = file.storedName;
    const previousStoragePath = file.storagePath;
    const previousStatus = file.status;
    const previousIntegrityStatus = file.integrityStatus;
    const previousOriginalStoredName = file.originalStoredName;
    const previousQuarantineStoredName = file.quarantineStoredName;

    let originalMoved = false;

    try {
        // Move the original file into the quarantine directory.
        await fs.rename(sourcePath, quarantinedPath);
        originalMoved = true;
        file.storedName = quarantinedStoredName;

        file.storagePath = path.join(
            "uploads",
            "quarantine",
            quarantinedStoredName
        );

        file.status = "quarantined";
        file.integrityStatus = "unavailable";

        file.originalStoredName = previousStoredName;
        file.quarantineStoredName = quarantinedStoredName;

        await file.save();
        
    } catch (error) {
        if (originalMoved) {
            try {
                await fs.rename(
                    quarantinedPath,
                    sourcePath
                );

                // Restore all modified document properties.
                file.storedName = previousStoredName;
                file.storagePath = previousStoragePath;
                file.status = previousStatus;
                file.integrityStatus = previousIntegrityStatus;

            } catch (rollbackError) {
                throw new AppError(
                    "Containment failed and filesystem rollback also failed. Manual investigation is required.",
                    500
                );
            }
        }

        throw error;
    }

    // Record the containment action after successful isolation.
    try {
        await securityEventService.createSecurityEvent({
            userId,
            fileId: file._id,
            eventType: "suspicious_activity",
            detectionType: "automatic_containment",
            episodeId: episodeId || crypto.randomUUID(),
            riskScore,
            reason: reason || "File isolated due to suspicious activity.",
            metadata: {
                action: "file_quarantined",
                riskLevel,
                originalStoredName: previousStoredName,
                quarantinedStoredName,
                backupAvailable,
                backupPreserved: true,
            },
        });
    } catch (error) {
        // Do not restore a suspicious file merely because audit logging failed.
        throw new AppError(
            "File was quarantined, but the containment security event could not be recorded. Audit investigation is required.",
            500
        );
    }

    return {
        fileId: String(file._id),
        status: "quarantined",
        quarantinedStoredName,
        backupAvailable,
    };
};

/**
 * Contains multiple files associated with a detection episode.
 */
const containFiles = async ({
    userId,
    fileIds,
    riskScore,
    riskLevel,
    episodeId,
    reason,
}) => {
    if (!Array.isArray(fileIds) || fileIds.length === 0) {
        throw new AppError(
            "At least one file ID is required.",
            400
        );
    }

    const uniqueFileIds = [...new Set(fileIds.map(String))];

    const results = [];

    for (const fileId of uniqueFileIds) {
        try {
            const result = await containFile({
                userId,
                fileId,
                riskScore,
                riskLevel,
                episodeId,
                reason,
            });

            results.push(result);
        } catch (error) {
            results.push({
                fileId,
                status: "failed",
                reason: error.message,
            });
        }
    }

    return {
        totalFiles: uniqueFileIds.length,
        quarantinedCount: results.filter(
            (result) => result.status === "quarantined"
        ).length,
        results,
    };
};

export default Object.freeze({
    containFile,
    containFiles,
});