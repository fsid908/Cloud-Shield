import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import File from "../models/file.model.js";
import AppError from "../utils/AppError.js";
import fileActivityService from "./fileActivity.service.js";
import storagePath from "../utils/storagePath.js";

const UPLOAD_DIRECTORY = path.resolve(
    process.cwd(),
    "uploads"
);

const BACKUP_DIRECTORY = path.join(
    UPLOAD_DIRECTORY,
    "backups"
);

// Calculate a SHA-256 hash for file integrity verification.
const calculateHash = (buffer) => {
    return crypto
        .createHash("sha256")
        .update(buffer)
        .digest("hex");
};

// Record recovery activity without masking the recovery result.
const recordRecoveryActivity = async ({
    userId,
    fileId,
    activityType,
    fileName,
}) => {
    try {
        await fileActivityService.recordFileActivity({
            userId,
            fileId,
            activityType,
            previousName: fileName,
            currentName: fileName,
        });
    } catch (error) {
        console.error("Recovery activity logging failed:", {
            fileId: String(fileId),
            activityType,
            message: error.message,
        });
    }
};

// Determine whether a file exists without hiding other filesystem errors.
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

// Remove a file when present, while preserving unexpected errors.
const removeFileIfExists = async (filePath) => {
    try {
        await fs.unlink(filePath);
    } catch (error) {
        if (error.code !== "ENOENT") {
            throw error;
        }
    }
};

// Recover a user's file from its trusted backup.
const recoverFile = async (fileId, userId) => {
    if (!fileId || !userId) {
        throw new AppError(
            "File ID and user ID are required.",
            400
        );
    }

    let file = null;

    try {
        // Find the file while enforcing user ownership.
        file = await File.findOne({
            _id: fileId,
            userId,
        });

        if (!file) {
            throw new AppError(
                "File not found or you do not have permission to access it.",
                404
            );
        }

        // Only safe files can be recovered.
if (file.status !== "safe") {
    throw new AppError(
        "Recovery is only available for safe files.",
        409
    );
}

        // A trusted backup requires both its stored filename and hash.
        if (!file.backupStoredName || !file.backupHash) {
            throw new AppError(
                "Trusted backup is not available for this file.",
                404
            );
        }

        // Resolve stored filenames inside their intended directories.
        const backupPath = storagePath.resolveStoragePath(
            BACKUP_DIRECTORY,
            file.backupStoredName
        );

        const currentFilePath = storagePath.resolveStoragePath(
            UPLOAD_DIRECTORY,
            file.storedName
        );

        let backupBuffer;

        try {
            backupBuffer = await fs.readFile(backupPath);
        } catch (error) {
            if (error.code === "ENOENT") {
                throw new AppError(
                    "Trusted backup file is unavailable.",
                    404
                );
            }

            throw error;
        }

        // Never restore a backup before verifying its integrity.
        const calculatedBackupHash = calculateHash(
            backupBuffer
        );

        if (calculatedBackupHash !== file.backupHash) {
            throw new AppError(
                "Trusted backup integrity verification failed.",
                409
            );
        }

        // Generate unique temporary and rollback filenames.
        const temporaryFilePath = path.join(
            path.dirname(currentFilePath),
            `.recovery-${crypto.randomUUID()}.tmp`
        );

        const rollbackFilePath = path.join(
            path.dirname(currentFilePath),
            `.rollback-${crypto.randomUUID()}.tmp`
        );

        const previousIntegrityStatus = file.integrityStatus;

        let temporaryFileCreated = false;
        let rollbackFileCreated = false;
        let originalFileExisted = false;
        let recoveredFileInstalled = false;

        try {
            // Write the verified backup to a new temporary file.
            // Create the temporary file exclusively so an existing file is never overwritten.
            const temporaryFileHandle = await fs.open(
                temporaryFilePath,
                "wx",
                0o600
            );

            // Track ownership immediately after successfully creating the file.
            // The cleanup block can now remove it even if writing fails.
            temporaryFileCreated = true;

            let writeError = null;

            try {
                await temporaryFileHandle.writeFile(backupBuffer);
            } catch (error) {
                writeError = error;
            }

            // Always attempt to close the file handle before continuing or failing.
            try {
                await temporaryFileHandle.close();
            } catch (error) {
                // Preserve the original write error if both operations fail.
                if (!writeError) {
                    writeError = error;
                }
            }

            if (writeError) {
                throw writeError;
            }

            // Verify the temporary file before touching the original.
            const temporaryBuffer = await fs.readFile(
                temporaryFilePath
            );

            const temporaryHash = calculateHash(
                temporaryBuffer
            );

            if (temporaryHash !== file.hash) {
                throw new AppError(
                    "Temporary recovery file verification failed.",
                    500
                );
            }

            // Determine whether there is an existing file to preserve.
            originalFileExisted = await fileExists(
                currentFilePath
            );

            if (originalFileExisted) {
                // Move the original aside before installing the recovery file.
                await fs.rename(
                    currentFilePath,
                    rollbackFilePath
                );

                rollbackFileCreated = true;
            }

            // The destination is now absent, avoiding replacement conflicts.
            await fs.rename(
                temporaryFilePath,
                currentFilePath
            );

            temporaryFileCreated = false;
            recoveredFileInstalled = true;

            // Verify the installed file, not just the temporary copy.
            const restoredBuffer = await fs.readFile(
                currentFilePath
            );

            const restoredHash = calculateHash(
                restoredBuffer
            );

            if (restoredHash !== file.hash) {
                throw new AppError(
                    "File recovery verification failed.",
                    500
                );
            }

            // Update the database only after verifying the restored file.
            file.integrityStatus = "intact";

            await file.save();
        } catch (recoveryError) {
            // Restore the previous in-memory state.
            file.integrityStatus = previousIntegrityStatus;

            try {
                if (rollbackFileCreated) {
                    // Remove the failed recovery result before restoring
                    // the original file to its previous location.
                    if (recoveredFileInstalled) {
                        await removeFileIfExists(
                            currentFilePath
                        );

                        recoveredFileInstalled = false;
                    }

                    await fs.rename(
                        rollbackFilePath,
                        currentFilePath
                    );

                    rollbackFileCreated = false;
                } else if (
                    recoveredFileInstalled &&
                    !originalFileExisted
                ) {
                    // The file did not exist before recovery.
                    // Restore that original state by removing the new file.
                    await removeFileIfExists(
                        currentFilePath
                    );

                    recoveredFileInstalled = false;
                }
            } catch (rollbackError) {
                // Preserve the rollback file for manual recovery.
                console.error(
                    "CRITICAL: Recovery rollback failed.",
                    {
                        fileId: String(file._id),
                        recoveryError: recoveryError.message,
                        rollbackError: rollbackError.message,
                        rollbackFilePath,
                    }
                );

                throw new AppError(
                    "Recovery failed and the previous file could not be restored. Manual recovery may be required.",
                    500
                );
            }

            // Preserve the original recovery error after successful rollback.
            throw recoveryError;
        } finally {
            // Remove the temporary file whenever it was created but not installed.
            // If it was renamed into place, temporaryFileCreated is already false.
            if (temporaryFileCreated) {
                try {
                    await removeFileIfExists(temporaryFilePath);
                    temporaryFileCreated = false;
                } catch (cleanupError) {
                    // Do not hide the original recovery error with a cleanup error.
                    console.error("Failed to clean up temporary recovery file.", {
                        fileId: String(file._id),
                        temporaryFilePath,
                        message: cleanupError.message,
                    });
                }
            }
        }

        // The database save succeeded. The rollback file is no longer needed.
        if (rollbackFileCreated) {
            try {
                await fs.unlink(rollbackFilePath);
                rollbackFileCreated = false;
            } catch (error) {
                // A cleanup failure must remain visible to operators.
                // Do not report recovery failure after a successful database save.
                console.error(
                    "Failed to clean up recovery rollback file.",
                    {
                        fileId: String(file._id),
                        rollbackFilePath,
                        message: error.message,
                    }
                );
            }
        }

        // Record successful recovery after persistence succeeds.
        await recordRecoveryActivity({
            userId,
            fileId: file._id,
            activityType: "recovered",
            fileName: file.originalName,
        });

        return {
            fileId: file._id,
            originalName: file.originalName,
            restoredHash: file.hash,
            integrityStatus: file.integrityStatus,
        };
    } catch (error) {
        // Only record failure when a user's file was successfully identified.
        if (file) {
            await recordRecoveryActivity({
                userId,
                fileId: file._id,
                activityType: "recovery_failed",
                fileName: file.originalName,
            });
        }

        throw error;
    }
};

export default {
    recoverFile,
};