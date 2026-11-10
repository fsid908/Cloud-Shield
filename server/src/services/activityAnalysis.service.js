import fileActivity from "../models/fileActivity.model.js";
import AppError from "../utils/AppError.js";

const analyzeRecentActivity = async (userId, windowSeconds = 30) => {
    if (!userId) {
        throw new AppError("User id is required.", 400);
    }

    if (!Number.isInteger(windowSeconds) || windowSeconds <= 0 || windowSeconds > 300) {
        throw new AppError("window must be between 1 and 300 seconds.", 400);
    }

    const windowStart = new Date(
        Date.now() - windowSeconds * 1000
    );

    const activities = await fileActivity.find({
        userId, createdAt: {
            $gte: windowStart,
        },
    })

        .select("fileId activityType previousExtension currentExtension createdAt")

        .sort({
            createdAt: -1,
        })
        .lean();

    const uniqueFiles = new Set(
        activities
    .filter((activity) => activity.fileId)
    .map((activity) => activity.fileId.toString())
    );

    const modifications = activities.filter((activity) => activity.activityType === "modified").length;

    const renames = activities.filter((activity) => activity.activityType === "renamed").length;

    const deletions = activities.filter((activity) => activity.activityType === "deleted").length;

    const extensionChanges = activities.filter((activity) => activity.previousExtension &&
        activity.currentExtension &&
        activity.previousExtension !== activity.currentExtension).length;

    return {
        windowSeconds, totalActivities: activities.length, uniqueFiles: uniqueFiles.size, modifications, renames, deletions, extensionChanges, activities,
    };
};

export default {
    analyzeRecentActivity,
};
