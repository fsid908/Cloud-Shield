import AppError from "../utils/AppError.js";
import RefreshSession from "../models/refreshSession.model.js";
import {
    generateRefreshToken,
    hashRefreshToken,
} from "../utils/refreshToken.js";
import jwt from "jsonwebtoken";
import env from "../config/env.js";
import User from "../models/user.model.js";

// refresh session configuration
const IDLE_TIMEOUT = 4 * 60 * 60 * 1000;
const REUSE_GRACE_PERIOD = 5 * 1000;

// refresh access token
const refreshAccessToken = async (refreshToken) => {

    // check refresh token
    if (!refreshToken) {
        throw new AppError("Refresh token is required.", 401);
    }

    // hash incoming refresh token
    const tokenHash = hashRefreshToken(refreshToken);

    // find refresh session
    const session = await RefreshSession.findOne({ tokenHash });

    // reject unknown refresh token
    if (!session) {
        throw new AppError("Invalid refresh token.", 401);
    }

    const now = new Date();

    // detect reuse of a revoked refresh token
    if (session.revokedAt) {

        const timeSinceRevocation =
            now.getTime() - session.revokedAt.getTime();

        // allow a short window for legitimate concurrent requests
        if (timeSinceRevocation > REUSE_GRACE_PERIOD) {

            // revoke all active sessions in the same token family
            await RefreshSession.updateMany(
                {
                    familyId: session.familyId,
                    revokedAt: null,
                },
                {
                    $set: {
                        revokedAt: now,
                    },
                }
            );
        }

        throw new AppError("Invalid or already used refresh token.", 401);
    }

    // check absolute session expiration
    if (session.expiresAt <= now) {

        await RefreshSession.findOneAndUpdate(
            {
                _id: session._id,
                revokedAt: null,
            },
            {
                $set: {
                    revokedAt: now,
                },
            }
        );

        throw new AppError("Refresh session has expired.", 401);
    }

    // check session inactivity
    const idleCutoff = new Date(
        now.getTime() - IDLE_TIMEOUT
    );

    if (session.lastUsedAt <= idleCutoff) {

        await RefreshSession.findOneAndUpdate(
            {
                _id: session._id,
                revokedAt: null,
            },
            {
                $set: {
                    revokedAt: now,
                },
            }
        );

        throw new AppError(
            "Refresh session has expired due to inactivity.",
            401
        );
    }

    // find the user linked to refresh session
    const user = await User.findById(session.userId);

    // reject session if user no longer exists
    if (!user) {

        await RefreshSession.findOneAndUpdate(
            {
                _id: session._id,
                revokedAt: null,
            },
            {
                $set: {
                    revokedAt: now,
                },
            }
        );

        throw new AppError("User account no longer exists.", 401);
    }

    // reject inactive account
    if (user.accountStatus !== "active") {

        await RefreshSession.findOneAndUpdate(
            {
                _id: session._id,
                revokedAt: null,
            },
            {
                $set: {
                    revokedAt: now,
                },
            }
        );

        throw new AppError("Account is not active.", 403);
    }

    // generate new access token
    const accessToken = jwt.sign(
        {
            userId: user._id.toString(),
            role: user.role,
        },
        env.JWT_SECRET,
        {
            expiresIn: "15m",
        }
    );

    // generate new refresh token
    const newRefreshToken = generateRefreshToken();

    // hash new refresh token
    const newTokenHash = hashRefreshToken(newRefreshToken);

    // atomically claim the existing refresh session
    const claimedSession = await RefreshSession.findOneAndUpdate(
        {
            _id: session._id,
            revokedAt: null,
            expiresAt: { $gt: now },
            lastUsedAt: { $gt: idleCutoff },
        },
        {
            $set: {
                revokedAt: now,
            },
        },
        {
            returnDocument: "before",
        }
    );

    // reject requests that failed to claim the session
    if (!claimedSession) {
        throw new AppError(
            "Refresh session is no longer valid.",
            401
        );
    }

    // create replacement refresh session
    const newSession = await RefreshSession.create({
        userId: user._id,
        familyId: session.familyId,
        tokenHash: newTokenHash,
        lastUsedAt: now,
        expiresAt: session.expiresAt,
        userAgent: session.userAgent,
        ipAddress: session.ipAddress,
    });

    return {
        accessToken,
        refreshToken: newRefreshToken,
        session: newSession,
    };
};

// revoke refresh session during logout
const revokeRefreshToken = async (refreshToken) => {

    // check refresh token
    if (!refreshToken) {
        return;
    }

    // hash incoming refresh token
    const tokenHash = hashRefreshToken(refreshToken);

    // atomically revoke active session
    await RefreshSession.findOneAndUpdate(
        {
            tokenHash,
            revokedAt: null,
        },
        {
            $set: {
                revokedAt: new Date(),
            },
        }
    );
};

export default {
    refreshAccessToken,
    revokeRefreshToken,
};