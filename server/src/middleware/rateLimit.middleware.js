import { rateLimit } from "express-rate-limit";

// rate limiter factory
export const createRateLimiter = ({ windowMs, limit, message }) => {
    return rateLimit({
        windowMs,
        limit,
        standardHeaders: true,
        legacyHeaders: false,
        handler: (req, res) => {
            return res.status(429).json({
                success: false,
                message,
            });
        },
    });
};

// login rate limiter
export const loginLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    message: "Too many login attempts. Please try again later.",
});

// registration rate limiter
export const registerLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000,
    limit: 5,
    message: "Too many registration attempts. Please try again later.",
});

// refresh token rate limiter
export const refreshLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    message: "Too many refresh attempts. Please try again later.",
});

// logout rate limiter
export const logoutLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    message: "Too many logout attempts. Please try again later.",
});