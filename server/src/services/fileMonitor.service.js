import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { watch } from "chokidar";

import File from "../models/file.model.js";
import securityEventService from "./securityEvent.service.js";

const UPLOAD_DIRECTORY = path.resolve(process.cwd(), "uploads");

const DEBOUNCE_MS = 250;
const DELETE_GRACE_MS = 500;

// Load trusted file metadata from MongoDB.
const loadTrackedFile = async (storedName) =>
    File.findOne({ storedName })
        .select("_id userId storedName originalName hash integrityStatus")
        .lean();

// Update the integrity status without replacing the entire document.
const updateIntegrityStatus = async (file, integrityStatus) =>
    File.updateOne(
        { _id: file._id, userId: file.userId },
        { $set: { integrityStatus } }
    );

// Persist detected integrity violations.
const persistIntegrityEvent = (event) =>
    securityEventService.createSecurityEvent(event);

// Create a monitor with injectable dependencies for isolated testing.
export const createFileMonitor = ({
    uploadsDirectory = UPLOAD_DIRECTORY,
    watchFactory = watch,
    findTrackedFile = loadTrackedFile,
    readFile = fs.readFile,
    setIntegrityStatus = updateIntegrityStatus,
    createIntegrityEvent = persistIntegrityEvent,
    debounceMs = DEBOUNCE_MS,
    deleteGraceMs = DELETE_GRACE_MS,
    logger = console,
} = {}) => {
    const rootDirectory = path.resolve(uploadsDirectory);
    const backupDirectory = path.join(rootDirectory, "backups");

    let watcher = null;
    let stopping = false;

    const pendingChecks = new Map();
    const lastReportedState = new Map();

    // Accept only files directly inside uploads, excluding backups.
    const getStoredName = (filePath) => {
        const absolutePath = path.resolve(filePath);

        if (path.dirname(absolutePath) !== rootDirectory) {
            return null;
        }

        return path.basename(absolutePath);
    };

    // Compare stored content with the trusted SHA-256 hash.
    const verifyTrackedFile = async (filePath, reportMissing) => {
        const storedName = getStoredName(filePath);

        if (!storedName || stopping) {
            return;
        }

        let file;

        try {
            file = await findTrackedFile(storedName);
        } catch (error) {
            logger.error("File monitor could not load metadata.", {
                storedName,
                message: error.message,
            });
            return;
        }

        // Ignore files without a trusted baseline.
        if (!file?.hash || stopping) {
            return;
        }

        let currentHash;
        let missing = false;

        try {
            const contents = await readFile(filePath);

            currentHash = crypto
                .createHash("sha256")
                .update(contents)
                .digest("hex");
        } catch (error) {
            if (error.code !== "ENOENT" || !reportMissing) {
                if (error.code !== "ENOENT") {
                    logger.error("File monitor could not read a tracked file.", {
                        storedName,
                        message: error.message,
                    });
                }

                return;
            }

            missing = true;
            currentHash = "missing";
        }

        if (stopping) {
            return;
        }

        const fileKey = String(file._id);

        const desiredStatus = missing
            ? "unavailable"
            : currentHash === file.hash
                ? "intact"
                : "modified";

        if (file.integrityStatus !== desiredStatus) {
            try {
                await setIntegrityStatus(file, desiredStatus);
            } catch (error) {
                logger.error("File monitor could not update integrity status.", {
                    fileId: fileKey,
                    message: error.message,
                });
                return;
            }
        }

        // Clear the duplicate-event marker after trusted content is restored.
        if (!missing && currentHash === file.hash) {
            lastReportedState.delete(fileKey);
            return;
        }

        // Avoid duplicate events for the same observed file state.
        if (lastReportedState.get(fileKey) === currentHash) {
            return;
        }

        try {
            await createIntegrityEvent({
                userId: file.userId,
                fileId: file._id,
                eventType: "integrity_violation",
                previousHash: file.hash,
                currentHash,
                riskScore: missing ? 30 : 10,
                reason: missing
                    ? "A tracked file is missing from server storage."
                    : "Stored file contents differ from the trusted baseline.",
                metadata: {
                    originalName: file.originalName,
                    source: "filesystem_monitor",
                    state: missing ? "missing" : "modified",
                },
            });

            // Mark the state only after event persistence succeeds.
            lastReportedState.set(fileKey, currentHash);

            logger.warn(
                "Cloud-Shield detected a stored-file integrity violation.",
                {
                    fileId: fileKey,
                    originalName: file.originalName,
                    state: missing ? "missing" : "modified",
                }
            );
        } catch (error) {
            logger.error("File monitor could not persist an integrity event.", {
                fileId: fileKey,
                message: error.message,
            });
        }
    };

    // Debounce noisy filesystem notifications for the same file.
    const scheduleCheck = (filePath, delayMs, reportMissing = false) => {
        const storedName = getStoredName(filePath);

        if (!storedName || stopping) {
            return;
        }

        const previousTimer = pendingChecks.get(storedName);

        if (previousTimer) {
            clearTimeout(previousTimer);
        }

        const timer = setTimeout(() => {
            pendingChecks.delete(storedName);

            verifyTrackedFile(filePath, reportMissing).catch((error) => {
                logger.error("Unhandled file-monitor verification error.", {
                    storedName,
                    message: error.message,
                });
            });
        }, delayMs);

        timer.unref?.();
        pendingChecks.set(storedName, timer);
    };

    const start = async () => {
        if (watcher) {
            return;
        }

        stopping = false;

        await fs.mkdir(rootDirectory, { recursive: true });

        const activeWatcher = watchFactory(rootDirectory, {
            ignoreInitial: false,
            persistent: true,
            awaitWriteFinish: {
                stabilityThreshold: 300,
                pollInterval: 100,
            },
            ignored: (candidatePath) => {
                const absolutePath = path.resolve(candidatePath);

                return (
                    absolutePath === backupDirectory ||
                    absolutePath.startsWith(`${backupDirectory}${path.sep}`)
                );
            },
        });

        watcher = activeWatcher;

        activeWatcher.on("add", (filePath) => {
            scheduleCheck(filePath, debounceMs);
        });

        activeWatcher.on("change", (filePath) => {
            scheduleCheck(filePath, debounceMs);
        });

        activeWatcher.on("unlink", (filePath) => {
            scheduleCheck(filePath, deleteGraceMs, true);
        });

        activeWatcher.on("error", (error) => {
            logger.error("Cloud-Shield filesystem monitor error.", error);
        });

        try {
            await new Promise((resolve, reject) => {
                const cleanup = () => {
                    activeWatcher.off("ready", onReady);
                    activeWatcher.off("error", onError);
                };

                const onReady = () => {
                    cleanup();
                    resolve();
                };

                const onError = (error) => {
                    cleanup();
                    reject(error);
                };

                activeWatcher.once("ready", onReady);
                activeWatcher.once("error", onError);
            });
        } catch (error) {
            watcher = null;
            await activeWatcher.close();
            throw error;
        }

        logger.info(
            "Cloud-Shield filesystem monitor is watching stored uploads."
        );
    };

    const stop = async () => {
        stopping = true;

        for (const timer of pendingChecks.values()) {
            clearTimeout(timer);
        }

        pendingChecks.clear();
        lastReportedState.clear();

        if (watcher) {
            const activeWatcher = watcher;
            watcher = null;

            await activeWatcher.close();
        }
    };

    return { start, stop };
};

// Export the production monitor instance.
const fileMonitor = createFileMonitor();

export default fileMonitor;