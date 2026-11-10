
import crypto from "node:crypto";

import AppError from "../utils/AppError.js";
import riskScorer from "../utils/riskScorer.js";
import activityAnalysisService from "./activityAnalysis.service.js";
import securityEventService from "./securityEvent.service.js";
import responseEngine from "./responseEngine.service.js";

const createEpisodeId = (signalType, activities) => {
  const activityIds = activities
    .map((activity) => String(activity._id))
    .sort();

  const identity = JSON.stringify({ signalType, activityIds });

  return crypto.createHash("sha256").update(identity).digest("hex");
};

const getAffectedFileIds = (activities) => [
  ...new Set(
    activities
      .filter((activity) => activity.fileId)
      .map((activity) => String(activity.fileId)),
  ),
];

const getTriggeringActivities = (signalType, activities) => {
  switch (signalType) {
    case "mass_file_modification":
    case "rapid_file_modification":
      return activities.filter(
        (activity) => activity.activityType === "modified",
      );

    case "multiple_extension_changes":
      return activities.filter(
        (activity) =>
          Boolean(activity.previousExtension) &&
          Boolean(activity.currentExtension) &&
          activity.previousExtension !== activity.currentExtension,
      );

    case "mass_file_rename":
      return activities.filter(
        (activity) => activity.activityType === "renamed",
      );

    case "mass_file_deletion":
      return activities.filter(
        (activity) => activity.activityType === "deleted",
      );

    default:
      return [];
  }
};

const persistDetectionSignals = async (
  userId,
  signals,
  activities,
  riskScore,
  responseDecision,
) => {
  const persistedEvents = [];

  for (const signal of signals) {
    const triggeringActivities = getTriggeringActivities(
      signal.type,
      activities,
    );

    if (
      triggeringActivities.length === 0 ||
      triggeringActivities.some(
        (activity) => !activity._id || !activity.fileId,
      )
    ) {
      continue;
    }

    const affectedFileIds = getAffectedFileIds(triggeringActivities);

    if (affectedFileIds.length === 0) continue;

    const episodeId = createEpisodeId(signal.type, triggeringActivities);

    const metadata = {
      severity: signal.severity,
      evidence: signal.evidence,
      triggeringActivityIds: triggeringActivities.map((activity) =>
        String(activity._id),
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
        eventType: "suspicious_activity",
        detectionType: signal.type,
        episodeId,
        riskScore,
        reason: signal.description,
        metadata,
      });

      persistedEvents.push(event);
    }
  }

  return persistedEvents;
};

const detectSuspiciousActivity = async (userId, windowSeconds = 30) => {
  if (!userId) {
    throw new AppError("User id is required.", 400);
  }

  if (
    !Number.isInteger(windowSeconds) ||
    windowSeconds <= 0 ||
    windowSeconds > 300
  ) {
    throw new AppError("Window must be between 1 and 300 seconds.", 400);
  }

  const analysis = await activityAnalysisService.analyzeRecentActivity(
    userId,
    windowSeconds,
  );

  const activities = analysis.activities;
  const signals = [];

  const modifiedActivities = activities.filter(
    (activity) => activity.activityType === "modified",
  );

  const deletedActivities = activities.filter(
    (activity) => activity.activityType === "deleted",
  );

  const modifiedFileIds = new Set(
    modifiedActivities
      .filter((activity) => activity.fileId)
      .map((activity) => String(activity.fileId)),
  );

  const deletedFileIds = new Set(
    deletedActivities
      .filter((activity) => activity.fileId)
      .map((activity) => String(activity.fileId)),
  );

  // Rule 1: Mass file modification.
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

  // Rule 2: Rapid file modification.
  if (analysis.modifications > 3 && analysis.windowSeconds <= 30) {
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

  // Rule 3: Multiple extension changes.
  if (analysis.extensionChanges >= 2 && analysis.windowSeconds <= 30) {
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
  if (analysis.renames >= 3 && analysis.windowSeconds <= 30) {
    signals.push({
      type: "mass_file_rename",
      severity: "medium",
      description: "Multiple files were renamed within a short period.",
      evidence: {
        renames: analysis.renames,
        windowSeconds: analysis.windowSeconds,
      },
    });
  }

  // Rule 5: Mass file deletion.
  if (analysis.deletions >= 3 && analysis.windowSeconds <= 30) {
    signals.push({
      type: "mass_file_deletion",
      severity: "high",
      description: "Multiple files were deleted within a short period.",
      evidence: {
        deletions: analysis.deletions,
        windowSeconds: analysis.windowSeconds,
      },
    });
  }

  const totalEvents =
    analysis.modifications +
    analysis.deletions +
    analysis.renames;

  const riskAssessment = riskScorer.calculateRiskScore({
    uniqueFilesModified: modifiedFileIds.size,
    uniqueFilesDeleted: deletedFileIds.size,
    totalEvents,
    windowSeconds: analysis.windowSeconds,
    extensionChanges: analysis.extensionChanges,
    renames: analysis.renames,
  });

  const riskLevel = riskScorer.getRiskLevel(riskAssessment.score);

  const responseDecision = responseEngine.determineResponse({
    riskScore: riskAssessment.score,
  });
  const events = await persistDetectionSignals(
    userId,
    signals,
    activities,
    riskAssessment.score,
    responseDecision,
  );
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
