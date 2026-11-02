import { describe, it } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { once } from "node:events";

import { createRateLimiter } from "../src/middleware/rateLimit.middleware.js";

// create a temporary HTTP server for testing
const createTestServer = async ({ limit, message }) => {
    const app = express();

    const limiter = createRateLimiter({
        windowMs: 60 * 1000,
        limit,
        message,
    });

    app.get("/test", limiter, (req, res) => {
        return res.status(200).json({
            success: true,
            message: "Request successful.",
        });
    });

    const server = app.listen(0, "127.0.0.1");

    await once(server, "listening");

    const address = server.address();

    return {
        server,
        baseUrl: `http://127.0.0.1:${address.port}`,
    };
};

// close the temporary HTTP server
const closeTestServer = async (server) => {
    if (!server.listening) return;

    await new Promise((resolve, reject) => {
        server.close((error) => {
            if (error) return reject(error);
            resolve();
        });
    });
};

describe("rateLimit.middleware", () => {
    it("should allow requests within the configured limit", async () => {
        const { server, baseUrl } = await createTestServer({
            limit: 2,
            message: "Too many requests.",
        });

        try {
            const firstResponse = await fetch(`${baseUrl}/test`);
            const secondResponse = await fetch(`${baseUrl}/test`);

            assert.equal(firstResponse.status, 200);
            assert.equal(secondResponse.status, 200);
        } finally {
            await closeTestServer(server);
        }
    });

    it("should return 429 when the configured limit is exceeded", async () => {
        const { server, baseUrl } = await createTestServer({
            limit: 2,
            message: "Too many requests. Please try again later.",
        });

        try {
            await fetch(`${baseUrl}/test`);
            await fetch(`${baseUrl}/test`);

            const response = await fetch(`${baseUrl}/test`);
            const body = await response.json();

            assert.equal(response.status, 429);

            assert.deepEqual(body, {
                success: false,
                message: "Too many requests. Please try again later.",
            });
        } finally {
            await closeTestServer(server);
        }
    });

    it("should maintain independent counters for separate limiters", async () => {
        const firstServer = await createTestServer({
            limit: 1,
            message: "First limiter exceeded.",
        });

        const secondServer = await createTestServer({
            limit: 1,
            message: "Second limiter exceeded.",
        });

        try {
            const firstResponse = await fetch(`${firstServer.baseUrl}/test`);
            const secondResponse = await fetch(`${secondServer.baseUrl}/test`);

            assert.equal(firstResponse.status, 200);
            assert.equal(secondResponse.status, 200);
        } finally {
            await closeTestServer(firstServer.server);
            await closeTestServer(secondServer.server);
        }
    });

    it("should return the configured error message", async () => {
        const customMessage = "Login attempts exceeded.";

        const { server, baseUrl } = await createTestServer({
            limit: 1,
            message: customMessage,
        });

        try {
            await fetch(`${baseUrl}/test`);

            const response = await fetch(`${baseUrl}/test`);
            const body = await response.json();

            assert.equal(response.status, 429);
            assert.equal(body.success, false);
            assert.equal(body.message, customMessage);
        } finally {
            await closeTestServer(server);
        }
    });
});