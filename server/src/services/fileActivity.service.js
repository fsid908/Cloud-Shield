
import FileActivity from "../models/fileActivity.model.js";
import AppError from "../utils/AppError.js";
import fileExtension from "../utils/fileExtension.js";
import detectionEngine from "./detectionEngine.service.js";

const DETECTION_WINDOW_SECONDS = 30;
const DETECTION_DEBOUNCE_MS = 1000;
const detectionTimers = new Map();

const scheduleDetection = (userId) => {
    const key = String(userId);
    clearTimeout(detectionTimers.get(key));

    const timer = setTimeout(async () => {
        detectionTimers.delete(key);

        try {
            await detectionEngine.detectSuspiciousActivity(
                userId,
                DETECTION_WINDOW_SECONDS
            );
        } catch (error) {
            console.error("Automatic threat detection failed.", {
                userId: key,
                message: error.message,
            });
        }
    }, DETECTION_DEBOUNCE_MS);

    timer.unref?.();
    detectionTimers.set(key, timer);
};

const recordFileActivity = async ({
    userId,
    fileId,
    activityType,
    previousName = null,
    currentName = null,
}) => {
    if (!userId || !fileId) {
        throw new AppError("User Id and File Id are required.", 400);
    }

    if (!activityType) {
        throw new AppError("activity type is required.", 400);
    }

    const previousExtension = fileExtension.getFileExtension(previousName);
    const currentExtension = fileExtension.getFileExtension(currentName);

    const activity = await FileActivity.create({
        userId,
        fileId,
        activityType,
        previousName,
        currentName,
        previousExtension,
        currentExtension,
    });

    if (["modified", "renamed", "deleted"].includes(activityType)) {
        scheduleDetection(userId);
    }

    return activity;
};

export default {
    recordFileActivity,
};
