
import FileActivity from "../models/fileActivity.model.js";
import AppError from "../utils/AppError.js";
import riskScorer from "../utils/riskScorer.js";

const getRecentIntegrityActivity = async (userId, windowSeconds = 30) => {
    if (!userId) {
        throw new AppError("User id is required.", 400);
    }

    if (
        !Number.isInteger(windowSeconds) ||
        windowSeconds <= 0 ||
        windowSeconds > 300
    ) {
        throw new AppError(
            "Window must be between 1 and 300 seconds.",
            400
        );
    }

    const windowStart = new Date(Date.now() - windowSeconds * 1000);

    const activities = await FileActivity.find({
        userId,
        createdAt: { $gte: windowStart },
    })
        .select("fileId activityType previousHash currentHash createdAt")
        .sort({ createdAt: -1 })
        .lean();

    const modifications = activities.filter(
        (activity) => activity.activityType === "modified"
    );

    const uniqueFilesModified = new Set(
        modifications
            .filter((activity) => activity.fileId)
            .map((activity) => String(activity.fileId))
    ).size;

    const risk = riskScorer.calculateRiskScore({
        uniqueFilesModified,
        totalEvents: modifications.length,
        windowSeconds,
    });

    return {
        windowSeconds,
        totalEvents: activities.length,
        uniqueFilesModified,
        riskScore: risk.score,
        riskLevel: riskScorer.getRiskLevel(risk.score),
        reasons: risk.reasons,
        events: activities,
    };
};

export default {
    getRecentIntegrityActivity,
};
