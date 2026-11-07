import crypto from "node:crypto";

import AppError from "../utils/AppError.js";
import activityAnalysisService from "./activityAnalysis.service.js";
import securityEventService from "./securityEvent.service.js";
import riskScorer from "../utils/riskScorer.js";
import responseEngine from "./responseEngine.service.js";



//  Generates a deterministic ID for a detection episode.

const createEpisodeId = (signalType, activities) => {
    const activityIds = activities
        .map((activity) => String(activity._id))
        .sort();

    const identity = JSON.stringify({
        signalType,
        activityIds,
    });

    return crypto
        .createHash("sha256")
        .update(identity)
        .digest("hex");
};


/**
 * Returns unique file IDs from the activities that triggered
 * a particular detection signal.
 */
const getAffectedFileIds = (activities) => {
    return [
        ...new Set(
            activities
                .filter((activity) => activity.fileId)
                .map((activity) => String(activity.fileId))
        ),
    ];
};


/**
 * Determines which activities are relevant to each detection rule.
 */
const getTriggeringActivities = (signalType, activities) => {
    switch (signalType) {
        case "mass_file_modification":
        case "rapid_file_modification":
            return activities.filter(
                (activity) => activity.activityType === "modified"
            );

        case "multiple_extension_changes":
            return activities.filter(
                (activity) =>
                    Boolean(activity.previousExtension) &&
                    Boolean(activity.currentExtension) &&
                    activity.previousExtension !==
                    activity.currentExtension
            );

        case "mass_file_rename":
            return activities.filter(
                (activity) => activity.activityType === "renamed"
            );

        default:
            return [];
    }
};


/**
 * Converts detection signals into persistent security events.
 *
 * Each affected file receives an event associated with the same
 * detection episode. SecurityEvent's existing schema requires
 * a fileId for every event.
 */
const persistDetectionSignals = async (
    userId,
    signals,
    activities,
    riskScore,
    responseDecision
) => {
    const persistedEvents = [];

    for (const signal of signals) {
        const triggeringActivities = getTriggeringActivities(
            signal.type,
            activities
        );

        // Incomplete evidence must not create an invalid event.
        if (
            triggeringActivities.length === 0 ||
            triggeringActivities.some(
                (activity) => !activity._id || !activity.fileId
            )
        ) {
            continue;
        }

        const affectedFileIds = getAffectedFileIds(
            triggeringActivities
        );

        if (affectedFileIds.length === 0) {
            continue;
        }

        const episodeId = createEpisodeId(
            signal.type,
            triggeringActivities
        );

        const eventType = "suspicious_activity";
        const reason = signal.description;

        const metadata = {
            severity: signal.severity,
            evidence: signal.evidence,

            triggeringActivityIds: triggeringActivities.map(
                (activity) => String(activity._id)
            ),

            response: {
                action: responseDecision.action,
                priority: responseDecision.priority,
                riskLevel: responseDecision.riskLevel,
                requiresContainment: responseDecision.requiresContainment,
                description: responseDecision.description,
                evaluatedAt: responseDecision.evaluatedAt,
            },
        };

        for (const fileId of affectedFileIds) {
            const event = await securityEventService.createSecurityEvent({
                userId,
                fileId,
                eventType,
                detectionType: signal.type,
                episodeId,
                riskScore,
                reason,
                metadata,
            });

            persistedEvents.push(event);
        }
    }

    return persistedEvents;
};


/**
 * Detects suspicious file activity and calculates its risk score.
 */
const detectSuspiciousActivity = async (
    userId,
    windowSeconds = 30
) => {
    // Validate user ID.
    if (!userId) {
        throw new AppError("User id is required.", 400);
    }

    // Validate analysis window.
    if (
        !Number.isInteger(windowSeconds) ||
        windowSeconds <= 0 ||
        windowSeconds > 300
    ) {
        throw new AppError(
            "Window must be between 1 and 300 seconds.",
            400
        );
    }

    // Step 1: Analyze recent file activity.
    const analysis =
        await activityAnalysisService.analyzeRecentActivity(
            userId,
            windowSeconds
        );

    const activities = analysis.activities;
    const signals = [];


    // Rule 1: At least three distinct modified files.
    const modifiedActivities = activities.filter(
        (activity) => activity.activityType === "modified"
    );

    const modifiedFileIds = new Set(
        modifiedActivities
            .filter((activity) => activity.fileId)
            .map((activity) => String(activity.fileId))
    );

    if (modifiedFileIds.size >= 3) {
        signals.push({
            type: "mass_file_modification",
            severity: "medium",
            description:
                "Multiple unique files were modified within a short period.",
            evidence: {
                uniqueFilesModified: modifiedFileIds.size,
                windowSeconds: analysis.windowSeconds,
            },
        });
    }


    // Rule 2: More than three modifications in a window
    // no longer than 30 seconds.
    if (
        analysis.modifications > 3 &&
        analysis.windowSeconds <= 30
    ) {
        signals.push({
            type: "rapid_file_modification",
            severity: "high",
            description:
                "More than 3 file modifications occurred within 30 seconds.",
            evidence: {
                modifications: analysis.modifications,
                windowSeconds: analysis.windowSeconds,
            },
        });
    }


    // Rule 3: Multiple file extension changes.
    if (
        analysis.extensionChanges >= 2 &&
        analysis.windowSeconds <= 30
    ) {
        signals.push({
            type: "multiple_extension_changes",
            severity: "high",
            description:
                "Multiple files changed their extensions within a short period.",
            evidence: {
                extensionChanges: analysis.extensionChanges,
                windowSeconds: analysis.windowSeconds,
            },
        });
    }


    // Rule 4: Mass file renaming.
    if (
        analysis.renames >= 3 &&
        analysis.windowSeconds <= 30
    ) {
        signals.push({
            type: "mass_file_rename",
            severity: "medium",
            description:
                "Multiple files were renamed within a short period.",
            evidence: {
                renames: analysis.renames,
                windowSeconds: analysis.windowSeconds,
            },
        });
    }


    // Step 2: Calculate overall activity risk score.
    const riskAssessment = riskScorer.calculateRiskScore({
        uniqueFilesModified: modifiedFileIds.size,
        totalEvents: analysis.modifications,
        windowSeconds: analysis.windowSeconds,
    });

    const riskLevel = riskScorer.getRiskLevel(
        riskAssessment.score
    );

    // Step 3: Determine the appropriate security response.
    const responseDecision = responseEngine.determineResponse({
        riskScore: riskAssessment.score,
    });


    // Step 4: Persist detection signals as security events.
    // Risk score is passed explicitly to avoid scope-related errors.
    const events = await persistDetectionSignals(
        userId,
        signals,
        activities,
        riskAssessment.score,
        responseDecision
    );


    // Step 5: Return detection and risk assessment results.
    
    return {
        windowSeconds: analysis.windowSeconds,

        signals,
        signalCount: signals.length,

        activity: analysis,

        events,
        persistedEventCount: events.length,

        riskScore: riskAssessment.score,
        riskLevel,
        riskReasons: riskAssessment.reasons,

        responseDecision,
    };
};


export default {
    detectSuspiciousActivity,
};