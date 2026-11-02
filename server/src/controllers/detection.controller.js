import detectionService from "../services/detection.service.js";
import { sendSuccess } from "../utils/response.js";
import detectionEngineService from "../services/detectionEngine.service.js";
import securityEventService from "../services/securityEvent.service.js";

const getRecentActivity = async (req, res, next) => {
    try{
        const userId = req.user._id;

        const windowSeconds = req.query.window ? Number(req.query.window) : 30;

        const activity = await detectionService.getRecentIntegrityActivity( userId, windowSeconds);

        return sendSuccess( res, 200, "Recent file activity retrieved successfully.", activity);
    } catch (error) {
        next(error)
    }
};
// Analyze recent activity for suspicious signals.
const detectSuspiciousActivity = async (req, res, next) => {
    try {
        const userId = req.user._id;

        const windowSeconds = req.query.window
            ? Number(req.query.window)
            : 30;

        const detection = await detectionEngineService.detectSuspiciousActivity(
            userId,
            windowSeconds
        );

        return sendSuccess(
            res,
            200,
            "Suspicious activity analysis completed.",
            detection
        );
    } catch (error) {
        next(error);
    }
};
const getSecurityEvents = async (req, res, next) => {
    try {
        const userId = req.user._id;

        const events = await securityEventService.getUserSecurityEvents(userId);

        return sendSuccess(
            res,
            200,
            "Security events retrieved successfully.",
            events
        );
    } catch (error) {
        next(error);
    }
};
export default {
    getRecentActivity,
    detectSuspiciousActivity,
    getSecurityEvents,
};