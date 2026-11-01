import SecurityEvent from "../models/securityEvent.model.js";
import AppError from "../utils/AppError.js";

const EVENT_TYPES = new Set([
    "integrity_violation",
    "suspicious_activity",
    "ransomware_detected",
]);

const DETECTION_EVENT_TYPES = new Set([
    "suspicious_activity",
    "ransomware_detected",
]);

const isDuplicateKeyError = (error) => error?.code === 11000;

const createSecurityEvent = async ({
    userId,
    fileId,
    eventType,
    previousHash = null,
    currentHash = null,
    detectionType = null,
    episodeId = null,
    riskScore = 0,
    reason,
    metadata = {},
}) => {
    if (!userId || !fileId) {
        throw new AppError(
            "User and file ID are required.",
            400
        );
    }

    if (!EVENT_TYPES.has(eventType)) {
        throw new AppError(
            "Invalid security event type.",
            400
        );
    }

    if (typeof reason !== "string" || !reason.trim()) {
        throw new AppError(
            "Security event reason is required.",
            400
        );
    }

    if (
        typeof riskScore !== "number" ||
        !Number.isFinite(riskScore) ||
        riskScore < 0 ||
        riskScore > 100
    ) {
        throw new AppError(
            "Risk score must be a number between 0 and 100.",
            400
        );
    }

    if (
        eventType === "integrity_violation" &&
        (
            typeof previousHash !== "string" ||
            !previousHash.trim() ||
            typeof currentHash !== "string" ||
            !currentHash.trim()
        )
    ) {
        throw new AppError(
            "Previous and current hashes are required for integrity violations.",
            400
        );
    }

    if (DETECTION_EVENT_TYPES.has(eventType)) {
        if (
            typeof detectionType !== "string" ||
            !detectionType.trim() ||
            typeof episodeId !== "string" ||
            !episodeId.trim()
        ) {
            throw new AppError(
                "Detection type and episode ID are required for detection events.",
                400
            );
        }
    }

    const eventIdentity = {
        userId,
        fileId,
        eventType,
        previousHash,
        currentHash,
        detectionType,
        episodeId,
    };

    const existingEvent = await SecurityEvent.findOne(
        eventIdentity
    );

    if (existingEvent) {
        return existingEvent;
    }

    try {
        return await SecurityEvent.create({
            ...eventIdentity,
            riskScore,
            reason: reason.trim(),
            metadata,
        });
    } catch (error) {
        // Let MongoDB's unique index arbitrate concurrent inserts.
        if (!isDuplicateKeyError(error)) {
            throw error;
        }

        const duplicateEvent = await SecurityEvent.findOne(
            eventIdentity
        );

        if (duplicateEvent) {
            return duplicateEvent;
        }

        // Don't hide a collision from an unrelated index.
        throw error;
    }
};

const getUserSecurityEvents = async (userId, limit = 20) => {
    if (!userId) {
        throw new AppError("User ID is required.", 400);
    }

    return SecurityEvent.find({ userId })
        .populate("fileId", "originalName storedName")
        .sort({ createdAt: -1 })
        .limit(limit)
        .lean();
};

export default {
    createSecurityEvent,
    getUserSecurityEvents,
};