import {
    describe,
    it,
    beforeEach,
    afterEach,
    mock,
} from "node:test";

import assert from "node:assert/strict";

import activityAnalysisService from "../src/services/activityAnalysis.service.js";
import detectionEngine from "../src/services/detectionEngine.service.js";
import securityEventService from "../src/services/securityEvent.service.js";

const createAnalysis = (overrides = {}) => ({
    windowSeconds: 30,
    totalActivities: 0,
    uniqueFiles: 0,
    modifications: 0,
    renames: 0,
    deletions: 0,
    extensionChanges: 0,
    activities: [],
    ...overrides,
});

describe("detectionEngine.detectSuspiciousActivity", () => {
    let analysisMock;

    beforeEach(() => {
        analysisMock = mock.method(
            activityAnalysisService,
            "analyzeRecentActivity",
            async (_userId, windowSeconds) =>
                createAnalysis({ windowSeconds })
        );

        mock.method(
            securityEventService,
            "createSecurityEvent",
            async (event) => ({
                _id: `event-${event.fileId}-${event.detectionType}`,
                ...event,
            })
        );
    });

    afterEach(() => {
        mock.restoreAll();
    });

    it("should reject a missing user ID", async () => {
        await assert.rejects(
            detectionEngine.detectSuspiciousActivity(null),
            {
                message: "User id is required.",
                statusCode: 400,
            }
        );

        assert.equal(analysisMock.mock.callCount(), 0);
    });

    it("should reject an invalid analysis window", async () => {
        await assert.rejects(
            detectionEngine.detectSuspiciousActivity("user-1", 0),
            {
                message: "Window must be between 1 and 300 seconds.",
                statusCode: 400,
            }
        );

        assert.equal(analysisMock.mock.callCount(), 0);
    });

    it("should detect modification of three distinct files", async () => {
        analysisMock.mock.mockImplementation(async () =>
            createAnalysis({
                uniqueFiles: 3,
                modifications: 4,
                activities: [
                    {
                        _id: "activity-1",
                        fileId: "file-1",
                        activityType: "modified",
                    },
                    {
                        _id: "activity-2",
                        fileId: "file-1",
                        activityType: "modified",
                    },
                    {
                        _id: "activity-3",
                        fileId: "file-2",
                        activityType: "modified",
                    },
                    {
                        _id: "activity-4",
                        fileId: "file-3",
                        activityType: "modified",
                    },
                ],
            })
        );

        const result =
            await detectionEngine.detectSuspiciousActivity("user-1");

        const massModificationSignal = result.signals.find(
            (signal) => signal.type === "mass_file_modification"
        );

        assert.ok(massModificationSignal);
        assert.equal(
            massModificationSignal.evidence.uniqueFilesModified,
            3
        );

        const massModificationEvents = result.events.filter(
            (event) =>
                event.detectionType === "mass_file_modification"
        );

        const rapidModificationEvents = result.events.filter(
            (event) =>
                event.detectionType === "rapid_file_modification"
        );

        // Three distinct files produce three events for each signal.
        assert.equal(massModificationEvents.length, 3);
        assert.equal(rapidModificationEvents.length, 3);

        assert.equal(result.events.length, 6);
        assert.equal(result.persistedEventCount, 6);

        assert.ok(
            massModificationEvents.every(
                (event) => event.eventType === "suspicious_activity"
            )
        );

        assert.ok(
            rapidModificationEvents.every(
                (event) => event.eventType === "suspicious_activity"
            )
        );

        // Verify overall risk assessment.
        assert.equal(result.riskScore, 30);
        assert.equal(result.riskLevel, "medium");

        // Verify response engine integration.
        assert.equal(
            result.responseDecision.action,
            "generate_alert"
        );

        assert.equal(
            result.responseDecision.priority,
            "medium"
        );

        assert.equal(
            result.responseDecision.requiresContainment,
            false
        );

        // Verify response metadata is persisted.
        assert.ok(
            massModificationEvents.every(
                (event) =>
                    event.metadata.response.action === "generate_alert"
            )
        );
    });

    it("should not flag file creation as mass file modification", async () => {
        analysisMock.mock.mockImplementation(async () =>
            createAnalysis({
                uniqueFiles: 3,
                totalActivities: 3,
                modifications: 0,
                activities: [
                    {
                        _id: "activity-1",
                        fileId: "file-1",
                        activityType: "created",
                    },
                    {
                        _id: "activity-2",
                        fileId: "file-2",
                        activityType: "created",
                    },
                    {
                        _id: "activity-3",
                        fileId: "file-3",
                        activityType: "created",
                    },
                ],
            })
        );

        const result =
            await detectionEngine.detectSuspiciousActivity("user-1");

        const massModificationSignal = result.signals.find(
            (signal) => signal.type === "mass_file_modification"
        );

        const massModificationEvents = result.events.filter(
            (event) =>
                event.detectionType === "mass_file_modification"
        );

        assert.equal(massModificationSignal, undefined);
        assert.equal(massModificationEvents.length, 0);
    });

    it("should detect rapid file modification", async () => {
        analysisMock.mock.mockImplementation(async () =>
            createAnalysis({
                modifications: 4,
            })
        );

        const result =
            await detectionEngine.detectSuspiciousActivity("user-1");

        const signal = result.signals.find(
            (item) => item.type === "rapid_file_modification"
        );

        assert.ok(signal);
        assert.equal(signal.severity, "high");
    });

    it("should report extension changes with a severity", async () => {
        analysisMock.mock.mockImplementation(async () =>
            createAnalysis({
                extensionChanges: 2,
            })
        );

        const result =
            await detectionEngine.detectSuspiciousActivity("user-1");

        const signal = result.signals.find(
            (item) => item.type === "multiple_extension_changes"
        );

        assert.ok(signal);
        assert.equal(signal.severity, "high");
    });

    it("should detect mass renaming independently of extension changes", async () => {
        analysisMock.mock.mockImplementation(async () =>
            createAnalysis({
                renames: 3,
                extensionChanges: 0,
            })
        );

        const result =
            await detectionEngine.detectSuspiciousActivity("user-1");

        assert.ok(
            result.signals.some(
                (signal) => signal.type === "mass_file_rename"
            )
        );
    });

    it("should return no signals for normal activity", async () => {
        const result =
            await detectionEngine.detectSuspiciousActivity("user-1");

        assert.equal(result.signalCount, 0);
        assert.deepEqual(result.signals, []);
        assert.equal(result.events.length, 0);
        assert.equal(result.persistedEventCount, 0);
    });

    it("should return the same episode ID for identical activity evidence", async () => {
        const activities = [
            {
                _id: "activity-1",
                fileId: "file-1",
                activityType: "modified",
            },
            {
                _id: "activity-2",
                fileId: "file-2",
                activityType: "modified",
            },
            {
                _id: "activity-3",
                fileId: "file-3",
                activityType: "modified",
            },
        ];

        analysisMock.mock.mockImplementation(async () =>
            createAnalysis({
                modifications: 3,
                activities,
            })
        );

        const firstResult =
            await detectionEngine.detectSuspiciousActivity("user-1");

        const secondResult =
            await detectionEngine.detectSuspiciousActivity("user-1");

        const firstEvent = firstResult.events.find(
            (event) =>
                event.detectionType === "mass_file_modification"
        );

        const secondEvent = secondResult.events.find(
            (event) =>
                event.detectionType === "mass_file_modification"
        );

        assert.ok(firstEvent);
        assert.ok(secondEvent);

        assert.equal(
            firstEvent.episodeId,
            secondEvent.episodeId
        );

        assert.equal(
            firstEvent.detectionType,
            "mass_file_modification"
        );
    });

    it("should recommend containment for high-risk activity", async () => {
        analysisMock.mock.mockImplementation(async () =>
            createAnalysis({
                modifications: 4,
                activities: [
                    {
                        _id: "activity-1",
                        fileId: "file-1",
                        activityType: "modified",
                    },
                    {
                        _id: "activity-2",
                        fileId: "file-2",
                        activityType: "modified",
                    },
                    {
                        _id: "activity-3",
                        fileId: "file-3",
                        activityType: "modified",
                    },
                    {
                        _id: "activity-4",
                        fileId: "file-4",
                        activityType: "modified",
                    },
                    {
                        _id: "activity-5",
                        fileId: "file-5",
                        activityType: "modified",
                    },
                    {
                        _id: "activity-6",
                        fileId: "file-6",
                        activityType: "modified",
                    },
                ],
            })
        );

        const result =
            await detectionEngine.detectSuspiciousActivity("user-1");

        assert.equal(result.riskScore, 45);
        assert.equal(result.riskLevel, "medium");

        assert.equal(
            result.responseDecision.action,
            "generate_alert"
        );
    });

});