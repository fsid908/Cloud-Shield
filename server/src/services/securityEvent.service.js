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
const getSecurityEvents = async ({
    userId,
    page = 1,
    limit = 10,
}) => {
    if (!userId) {
        throw new AppError(
            "User ID is required.",
            400
        );
    }

    if (
        !Number.isSafeInteger(page) ||
        page < 1
    ) {
        throw new AppError(
            "Page must be a positive integer.",
            400
        );
    }

    if (
        !Number.isSafeInteger(limit) ||
        limit < 1 ||
        limit > 100
    ) {
        throw new AppError(
            "Limit must be an integer between 1 and 100.",
            400
        );
    }

    const filter = { userId };

    const [events, total] = await Promise.all([
        SecurityEvent.find(filter)
    .populate("fileId", "originalName storedName")
    .sort({ createdAt: -1, _id: -1 })
    .skip((page - 1) * limit)
    .limit(limit)
    .lean(),

        SecurityEvent.countDocuments(filter),
    ]);

    return {
        events,
        pagination: {
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit),
        },
    };
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
    getSecurityEvents,
};