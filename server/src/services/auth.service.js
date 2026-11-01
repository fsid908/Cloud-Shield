import bcrypt from "bcryptjs";
import crypto from "crypto";
import jwt from "jsonwebtoken";

import User from "../models/user.model.js";
import RefreshSession from "../models/refreshSession.model.js";
import AppError from "../utils/AppError.js";
import env from "../config/env.js";
import {
    generateRefreshToken,
    hashRefreshToken,
} from "../utils/refreshToken.js";

const registerUser = async (userData) => {
    const { fullName, email, password } = userData;

    // check if user already exists
    const existingUser = await User.findOne({ email });

    if (existingUser) {
        throw new AppError("Email already exists.", 409);
    }

    // hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // create user
    const newUser = await User.create({
        fullName,
        email,
        password: hashedPassword,
    });

    // remove password before returning
    const userResponse = newUser.toObject();
    delete userResponse.password;

    return userResponse;
};

// login user
const loginUser = async (email, password, sessionInfo = {}) => {
    const user = await User.findOne({ email });

    // use generic error to prevent account enumeration
    if (!user) {
        throw new AppError("Invalid email or password.", 401);
    }

    // check account status
    if (user.accountStatus !== "active") {
        throw new AppError("Account is not active.", 403);
    }

    // compare password with stored bcrypt hash
    const isPasswordValid = await bcrypt.compare(
        password,
        user.password
    );

    // reject invalid credentials
    if (!isPasswordValid) {
        throw new AppError("Invalid email or password.", 401);
    }

    // update last successful login time
    user.lastLogin = new Date();
    await user.save();

    // generate short-lived access token
    const token = jwt.sign(
        {
            userId: user._id.toString(),
            role: user.role,
        },
        env.JWT_SECRET,
        {
            expiresIn: "15m",
        }
    );

    // generate refresh token
    const refreshToken = generateRefreshToken();

    // hash refresh token before storing
    const refreshTokenHash = hashRefreshToken(refreshToken);

    // create refresh session timestamps
    const now = new Date();

    const refreshExpiresAt = new Date(
        now.getTime() + 7 * 24 * 60 * 60 * 1000
    );

    // create unique refresh-token family for this login session
    const familyId = crypto.randomUUID();

    // create refresh session
    await RefreshSession.create({
        userId: user._id,
        familyId,
        tokenHash: refreshTokenHash,
        lastUsedAt: now,
        expiresAt: refreshExpiresAt,
        userAgent: sessionInfo.userAgent || null,
        ipAddress: sessionInfo.ipAddress || null,
    });

    // remove password before returning user
    const userResponse = user.toObject();
    delete userResponse.password;

    // return authentication data
    return {
        user: userResponse,
        token,
        refreshToken,
    };
};
const updateUserProfile = async (userId, profileData) => {
    const { fullName } = profileData;

    const user = await User.findById(userId);

    if (!user) {
        throw new AppError("User not found.", 404);
    }

    user.fullName = fullName;
    await user.save();

    const userResponse = user.toObject();
    delete userResponse.password;

    return userResponse;
};

export default {
    registerUser,
    loginUser,
    updateUserProfile,
};