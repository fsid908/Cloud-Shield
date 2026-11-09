const calculateRiskScore = ({
    uniqueFilesModified = 0,
    uniqueFilesDeleted = 0,
    totalEvents = 0,
    windowSeconds,
    extensionChanges = 0,
    renames = 0,
}) => {
    const inputs = {
        uniqueFilesModified,
        uniqueFilesDeleted,
        totalEvents,
        windowSeconds,
        extensionChanges,
        renames,
    };

    // Validate numeric inputs.
    for (const [key, value] of Object.entries(inputs)) {
        if (
            typeof value !== "number" ||
            !Number.isFinite(value) ||
            !Number.isInteger(value) ||
            value < 0
        ) {
            throw new TypeError(
                `${key} must be a non-negative integer.`
            );
        }
    }

    if (windowSeconds === 0) {
        throw new TypeError(
            "windowSeconds must be greater than zero."
        );
    }

    let score = 0;
    const reasons = [];

    // 1. Modified file risk.
    if (uniqueFilesModified > 10) {
        score += 35;
        reasons.push(
            "More than 10 unique files were modified."
        );
    } else if (uniqueFilesModified >= 6) {
        score += 25;
        reasons.push(
            "6 to 10 unique files were modified."
        );
    } else if (uniqueFilesModified >= 3) {
        score += 15;
        reasons.push(
            "3 to 5 unique files were modified."
        );
    } else if (uniqueFilesModified >= 1) {
        score += 5;
        reasons.push(
            "File modification activity was detected."
        );
    }

    // 2. Deleted file risk.
    if (uniqueFilesDeleted >= 10) {
        score += 30;
        reasons.push(
            "10 or more unique files were deleted."
        );
    } else if (uniqueFilesDeleted >= 5) {
        score += 20;
        reasons.push(
            "5 to 9 unique files were deleted."
        );
    } else if (uniqueFilesDeleted >= 2) {
        score += 10;
        reasons.push(
            "2 to 4 unique files were deleted."
        );
    }

    // 3. Suspicious event frequency.
    if (windowSeconds <= 30) {
        if (totalEvents > 10) {
            score += 20;
            reasons.push(
                "More than 10 suspicious events occurred within 30 seconds."
            );
        } else if (totalEvents > 3) {
            score += 10;
            reasons.push(
                "More than 3 suspicious events occurred within 30 seconds."
            );
        }
    }

    // 4. File extension changes.
    if (extensionChanges >= 5) {
        score += 10;
        reasons.push(
            "5 or more file extension changes were detected."
        );
    } else if (extensionChanges >= 2) {
        score += 5;
        reasons.push(
            "Multiple file extension changes were detected."
        );
    }

    // 5. File renaming activity.
    if (renames >= 5) {
        score += 5;
        reasons.push(
            "5 or more file renames were detected."
        );
    } else if (renames >= 3) {
        score += 3;
        reasons.push(
            "Multiple file renames were detected."
        );
    }

    return {
        score: Math.min(score, 100),
        reasons,
    };
};

const getRiskLevel = (score) => {
    if (
        typeof score !== "number" ||
        !Number.isFinite(score) ||
        score < 0 ||
        score > 100
    ) {
        throw new TypeError(
            "Risk score must be a finite number between 0 and 100."
        );
    }

    if (score >= 80) {
        return "critical";
    }

    if (score >= 60) {
        return "high";
    }

    if (score >= 30) {
        return "medium";
    }

    return "low";
};

export default {
    calculateRiskScore,
    getRiskLevel,
};