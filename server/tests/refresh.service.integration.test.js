import assert from "node:assert/strict";
import crypto from "node:crypto";
import dotenv from "dotenv";
import mongoose from "mongoose";
import { after, before, describe, it } from "node:test";

import User from "../src/models/user.model.js";
import RefreshSession from "../src/models/refreshSession.model.js";

import refreshService from "../src/services/refresh.service.js";

import {
    generateRefreshToken,
    hashRefreshToken,
} from "../src/utils/refreshToken.js";

// load test database configuration
dotenv.config({ path: ".env.test" });

const testUri = process.env.MONGODB_TEST_URI;

const testUserIds = [];

// create test user
const createTestUser = async (overrides = {}) => {
    const user = await User.create({
        fullName: "Refresh Test User",
        email: `refresh-${crypto.randomUUID()}@example.com`,
        password: "test-password-hash",
        ...overrides,
    });

    testUserIds.push(user._id);

    return user;
};

// create refresh session
const createTestSession = async (userId, overrides = {}) => {
    const refreshToken = generateRefreshToken();

    const now = new Date();

    const session = await RefreshSession.create({
        userId,
        familyId: crypto.randomUUID(),
        tokenHash: hashRefreshToken(refreshToken),
        lastUsedAt: now,
        expiresAt: new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000),
        ...overrides,
    });

    return {
        refreshToken,
        session,
    };
};

describe(
    "Refresh service MongoDB integration tests",
    { skip: !testUri },
    () => {

        before(async () => {

            // protect non-test databases
            const databaseName = new URL(testUri).pathname
                .replace(/^\/+/, "");

            assert.match(
                databaseName,
                /(?:_|-)test$/i,
                "MONGODB_TEST_URI must target a test database"
            );

            await mongoose.connect(testUri);
        });

        after(async () => {
            try {

                // remove only test-created records
                if (
                    mongoose.connection.readyState === 1 &&
                    testUserIds.length > 0
                ) {
                    await RefreshSession.deleteMany({
                        userId: { $in: testUserIds },
                    });

                    await User.deleteMany({
                        _id: { $in: testUserIds },
                    });
                }

            } finally {
                if (mongoose.connection.readyState !== 0) {
                    await mongoose.disconnect();
                }
            }
        });

        it("rotates a valid refresh token successfully", async () => {
            const user = await createTestUser();

            const { refreshToken, session } =
                await createTestSession(user._id);

            const result = await refreshService.refreshAccessToken(
                refreshToken
            );

            assert.ok(result.accessToken);
            assert.ok(result.refreshToken);

            assert.notEqual(
                result.refreshToken,
                refreshToken
            );

            const oldSession = await RefreshSession.findById(
                session._id
            );

            const newSession = await RefreshSession.findOne({
                tokenHash: hashRefreshToken(result.refreshToken),
            });

            assert.ok(oldSession.revokedAt);
            assert.ok(newSession);

            assert.equal(
                newSession.familyId.toString(),
                session.familyId.toString()
            );

            assert.equal(
                newSession.expiresAt.getTime(),
                session.expiresAt.getTime()
            );
        });

        it("rejects an unknown refresh token", async () => {
            await assert.rejects(
                refreshService.refreshAccessToken(
                    generateRefreshToken()
                ),
                (error) => error.statusCode === 401
            );
        });

        it("revokes an expired refresh session", async () => {
            const user = await createTestUser();

            const { refreshToken, session } =
                await createTestSession(user._id, {
                    expiresAt: new Date(Date.now() - 1000),
                });

            await assert.rejects(
                refreshService.refreshAccessToken(refreshToken),
                (error) => error.statusCode === 401
            );

            const updatedSession = await RefreshSession.findById(
                session._id
            );

            assert.ok(updatedSession.revokedAt);
        });

        it("revokes an inactive refresh session", async () => {
            const user = await createTestUser();

            const { refreshToken, session } =
                await createTestSession(user._id, {
                    lastUsedAt: new Date(
                        Date.now() - 4 * 60 * 60 * 1000 - 1000
                    ),
                });

            await assert.rejects(
                refreshService.refreshAccessToken(refreshToken),
                (error) => error.statusCode === 401
            );

            const updatedSession = await RefreshSession.findById(
                session._id
            );

            assert.ok(updatedSession.revokedAt);
        });

        it("revokes the session when the account is suspended", async () => {
            const user = await createTestUser({
                accountStatus: "suspended",
            });

            const { refreshToken, session } =
                await createTestSession(user._id);

            await assert.rejects(
                refreshService.refreshAccessToken(refreshToken),
                (error) => error.statusCode === 403
            );

            const updatedSession = await RefreshSession.findById(
                session._id
            );

            assert.ok(updatedSession.revokedAt);
        });

        it("revokes the session when the user no longer exists", async () => {
            const user = await createTestUser();

            const { refreshToken, session } =
                await createTestSession(user._id);

            await User.deleteOne({
                _id: user._id,
            });

            await assert.rejects(
                refreshService.refreshAccessToken(refreshToken),
                (error) => error.statusCode === 401
            );

            const updatedSession = await RefreshSession.findById(
                session._id
            );

            assert.ok(updatedSession.revokedAt);
        });

        it("allows only one successful concurrent refresh", async () => {
            const user = await createTestUser();

            const { refreshToken, session } =
                await createTestSession(user._id);

            const results = await Promise.allSettled([
                refreshService.refreshAccessToken(refreshToken),
                refreshService.refreshAccessToken(refreshToken),
            ]);

            const successfulRequests = results.filter(
                (result) => result.status === "fulfilled"
            );

            const failedRequests = results.filter(
                (result) => result.status === "rejected"
            );

            assert.equal(successfulRequests.length, 1);
            assert.equal(failedRequests.length, 1);

            const oldSession = await RefreshSession.findById(
                session._id
            );

            assert.ok(oldSession.revokedAt);

            const activeSessions = await RefreshSession.find({
                familyId: session.familyId,
                revokedAt: null,
            });

            assert.equal(activeSessions.length, 1);
        });

        it("revokes the active token family when an old token is reused", async () => {
            const user = await createTestUser();

            const { refreshToken, session } =
                await createTestSession(user._id);

            const result = await refreshService.refreshAccessToken(
                refreshToken
            );

            // simulate reuse outside the concurrency grace period
            await RefreshSession.updateOne(
                { _id: session._id },
                {
                    $set: {
                        revokedAt: new Date(Date.now() - 6000),
                    },
                }
            );

            await assert.rejects(
                refreshService.refreshAccessToken(refreshToken),
                (error) => error.statusCode === 401
            );

            const activeSessions = await RefreshSession.countDocuments({
                familyId: session.familyId,
                revokedAt: null,
            });

            assert.equal(activeSessions, 0);

            // confirm replacement session was also revoked
            const replacement = await RefreshSession.findOne({
                tokenHash: hashRefreshToken(result.refreshToken),
            });

            assert.ok(replacement.revokedAt);
        });

        it("revokes a refresh session during logout", async () => {
            const user = await createTestUser();

            const { refreshToken, session } =
                await createTestSession(user._id);

            await refreshService.revokeRefreshToken(refreshToken);

            const updatedSession = await RefreshSession.findById(
                session._id
            );

            assert.ok(updatedSession.revokedAt);
        });
    }
);