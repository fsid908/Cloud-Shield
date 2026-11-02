import {
    describe,
    it,
    afterEach,
    mock,
} from "node:test";

import assert from "node:assert/strict";

import SecurityEvent from "../src/models/securityEvent.model.js";

import securityEventService from "../src/services/securityEvent.service.js";

const validEvent = (overrides = {}) => ({
    userId: "user-1",
    fileId: "file-1",
    eventType: "integrity_violation",
    previousHash: "trusted-hash",
    currentHash: "changed-hash",
    riskScore: 10,
    reason: "File contents differ from the trusted baseline.",
    metadata: {
        originalName: "report.txt",
    },
    ...overrides,
});

describe("securityEvent.createSecurityEvent", () => {
    afterEach(() => {
        mock.restoreAll();
    });

    it("should reject missing user or file IDs", async () => {
        const findMock = mock.method(
            SecurityEvent,
            "findOne",
            async () => {
                throw new Error(
                    "Database must not be queried"
                );
            }
        );

        await assert.rejects(
            securityEventService.createSecurityEvent(
                validEvent({ userId: null })
            ),
            {
                message: "User and file ID are required.",
                statusCode: 400,
            }
        );

        await assert.rejects(
            securityEventService.createSecurityEvent(
                validEvent({ fileId: null })
            ),
            {
                message: "User and file ID are required.",
                statusCode: 400,
            }
        );

        assert.equal(findMock.mock.callCount(), 0);
    });

    it("should reject invalid event types", async () => {
        const findMock = mock.method(
            SecurityEvent,
            "findOne",
            async () => {
                throw new Error(
                    "Database must not be queried"
                );
            }
        );

        await assert.rejects(
            securityEventService.createSecurityEvent(
                validEvent({ eventType: "invalid_event" })
            ),
            {
                message: "Invalid security event type.",
                statusCode: 400,
            }
        );

        assert.equal(findMock.mock.callCount(), 0);
    });

    it("should reject an empty reason", async () => {
        const findMock = mock.method(
            SecurityEvent,
            "findOne",
            async () => {
                throw new Error(
                    "Database must not be queried"
                );
            }
        );

        await assert.rejects(
            securityEventService.createSecurityEvent(
                validEvent({ reason: "   " })
            ),
            {
                message: "Security event reason is required.",
                statusCode: 400,
            }
        );

        assert.equal(findMock.mock.callCount(), 0);
    });

    it("should reject invalid risk scores", async () => {
        const findMock = mock.method(
            SecurityEvent,
            "findOne",
            async () => {
                throw new Error(
                    "Database must not be queried"
                );
            }
        );

        for (const riskScore of [
            NaN,
            Infinity,
            -Infinity,
            "10",
            -1,
            101,
        ]) {
            await assert.rejects(
                securityEventService.createSecurityEvent(
                    validEvent({ riskScore })
                ),
                {
                    message:
                        "Risk score must be a number between 0 and 100.",
                    statusCode: 400,
                }
            );
        }

        assert.equal(findMock.mock.callCount(), 0);
    });

    it("should return an existing event without creating a duplicate", async () => {
        const existingEvent = {
            _id: "event-1",
            ...validEvent(),
        };

        const findMock = mock.method(
            SecurityEvent,
            "findOne",
            async () => existingEvent
        );

        const createMock = mock.method(
            SecurityEvent,
            "create",
            async () => {
                throw new Error(
                    "Create must not run for an existing event"
                );
            }
        );

        const result =
            await securityEventService.createSecurityEvent(
                validEvent()
            );

        assert.equal(result, existingEvent);
        assert.equal(findMock.mock.callCount(), 1);
        assert.equal(createMock.mock.callCount(), 0);
    });

    it("should create a new event when no duplicate exists", async () => {
        const findMock = mock.method(
            SecurityEvent,
            "findOne",
            async () => null
        );

        const createMock = mock.method(
            SecurityEvent,
            "create",
            async (document) => ({
                _id: "event-2",
                ...document,
            })
        );

        const result =
            await securityEventService.createSecurityEvent(
                validEvent({
                    reason: "  modified file contents  ",
                })
            );

        assert.equal(result._id, "event-2");
        assert.equal(findMock.mock.callCount(), 1);
        assert.equal(createMock.mock.callCount(), 1);

        assert.equal(
            createMock.mock.calls[0].arguments[0].reason,
            "modified file contents"
        );
    });

    it("should handle a concurrent duplicate-key race", async () => {
        const existingEvent = {
            _id: "event-3",
            ...validEvent(),
        };

        let findCount = 0;

        const findMock = mock.method(
            SecurityEvent,
            "findOne",
            async () => {
                findCount += 1;

                return findCount === 1
                    ? null
                    : existingEvent;
            }
        );

        const createMock = mock.method(
            SecurityEvent,
            "create",
            async () => {
                const error = new Error("duplicate key");
                error.code = 11000;
                throw error;
            }
        );

        const result =
            await securityEventService.createSecurityEvent(
                validEvent()
            );

        assert.equal(result, existingEvent);
        assert.equal(findMock.mock.callCount(), 2);
        assert.equal(createMock.mock.callCount(), 1);
    });

    it("should propagate unrelated database errors", async () => {
        const databaseError = new Error(
            "database unavailable"
        );

        mock.method(
            SecurityEvent,
            "findOne",
            async () => null
        );

        mock.method(
            SecurityEvent,
            "create",
            async () => {
                throw databaseError;
            }
        );

        await assert.rejects(
            securityEventService.createSecurityEvent(
                validEvent()
            ),
            (error) => error === databaseError
        );
    });

    it("should reject detection events without an episode identity", async () => {
        const findMock = mock.method(
            SecurityEvent,
            "findOne",
            async () => {
                throw new Error("Database must not be queried");
            }
        );

        await assert.rejects(
            securityEventService.createSecurityEvent({
                userId: "user-1",
                fileId: "file-1",
                eventType: "suspicious_activity",
                detectionType: "mass_file_modification",
                riskScore: 40,
                reason: "Multiple files were modified rapidly.",
            }),
            {
                message:
                    "Detection type and episode ID are required for detection events.",
                statusCode: 400,
            }
        );

        assert.equal(findMock.mock.callCount(), 0);
    });

    it("should define separate partial unique indexes for transitions and episodes", () => {
        const indexes = SecurityEvent.schema.indexes();

        const transitionIndex = indexes.find(
            ([, options]) =>
                options.name ===
                "unique_security_event_transition_integrity"
        );

        const episodeIndex = indexes.find(
            ([, options]) =>
                options.name === "unique_security_event_episode"
        );

        assert.ok(transitionIndex);
        assert.ok(transitionIndex[1].unique);

        assert.deepEqual(
            transitionIndex[1].partialFilterExpression,
            {
                eventType: "integrity_violation",
            }
        );

        assert.ok(episodeIndex);
        assert.ok(episodeIndex[1].unique);

        assert.deepEqual(
            episodeIndex[1].partialFilterExpression,
            {
                episodeId: {
                    $type: "string",
                },
            }
        );
    });
});

describe("securityEvent.getSecurityEvents", () => {
    afterEach(() => {
        mock.restoreAll();
    });

    it("should reject a missing user ID", async () => {
        await assert.rejects(
            securityEventService.getSecurityEvents({
                userId: null,
            }),
            {
                message: "User ID is required.",
                statusCode: 400,
            }
        );
    });

    it("should reject invalid page values", async () => {
        for (const page of [0, -1, 1.5, NaN, Infinity]) {
            await assert.rejects(
                securityEventService.getSecurityEvents({
                    userId: "user-1",
                    page,
                }),
                {
                    message: "Page must be a positive integer.",
                    statusCode: 400,
                }
            );
        }
    });

    it("should reject invalid limits", async () => {
        for (const limit of [0, -1, 1.5, 101, NaN, Infinity]) {
            await assert.rejects(
                securityEventService.getSecurityEvents({
                    userId: "user-1",
                    limit,
                }),
                {
                    message:
                        "Limit must be an integer between 1 and 100.",
                    statusCode: 400,
                }
            );
        }
    });

    it("should return paginated events scoped to the requested user", async () => {
        const events = [
            { _id: "event-2", userId: "user-1" },
            { _id: "event-1", userId: "user-1" },
        ];

        const query = {
            sort: mock.fn(() => query),
            skip: mock.fn(() => query),
            limit: mock.fn(() => query),
            lean: mock.fn(async () => events),
        };

        const findMock = mock.method(
            SecurityEvent,
            "find",
            (filter) => {
                assert.deepEqual(filter, {
                    userId: "user-1",
                });

                return query;
            }
        );

        const countMock = mock.method(
            SecurityEvent,
            "countDocuments",
            async (filter) => {
                assert.deepEqual(filter, {
                    userId: "user-1",
                });

                return 12;
            }
        );

        const result =
            await securityEventService.getSecurityEvents({
                userId: "user-1",
                page: 2,
                limit: 2,
            });

        assert.deepEqual(result, {
            events,
            pagination: {
                page: 2,
                limit: 2,
                total: 12,
                totalPages: 6,
            },
        });

        assert.deepEqual(
            query.sort.mock.calls[0].arguments[0],
            { createdAt: -1, _id: -1 }
        );

        assert.equal(
            query.skip.mock.calls[0].arguments[0],
            2
        );

        assert.equal(
            query.limit.mock.calls[0].arguments[0],
            2
        );

        assert.equal(findMock.mock.callCount(), 1);
        assert.equal(countMock.mock.callCount(), 1);
    });

    it("should propagate database errors", async () => {
        const databaseError = new Error(
            "database unavailable"
        );

        mock.method(
            SecurityEvent,
            "find",
            () => {
                throw databaseError;
            }
        );

        mock.method(
            SecurityEvent,
            "countDocuments",
            async () => 0
        );

        await assert.rejects(
            securityEventService.getSecurityEvents({
                userId: "user-1",
            }),
            (error) => error === databaseError
        );
    });
});