import securityEventService from "../services/securityEvent.service.js";
import { sendSuccess } from "../utils/response.js";

const getSecurityEvents = async (req, res, next) => {
    try {
        const userId = req.user._id;

        const page = req.query.page === undefined
            ? 1
            : Number(req.query.page);

        const limit = req.query.limit === undefined
            ? 10
            : Number(req.query.limit);

        const result = await securityEventService.getSecurityEvents({
            userId,
            page,
            limit,
        });

        return sendSuccess(
            res,
            200,
            "Security events retrieved successfully.",
            result
        );
    } catch (error) {
        next(error);
    }
};

export default {
    getSecurityEvents,
};
