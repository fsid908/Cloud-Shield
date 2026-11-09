const RESPONSE_POLICIES = Object.freeze({
    low: Object.freeze({
        action: "monitor",
        priority: "low",
        requiresContainment: false,
        description: "Continue monitoring file activity.",
    }),

    medium: Object.freeze({
        action: "generate_alert",
        priority: "medium",
        requiresContainment: false,
        description: "Suspicious activity detected. Notify the user.",
    }),

    high: Object.freeze({
        action: "recommend_containment",
        priority: "high",
        requiresContainment: true,
        description:
            "High-risk activity detected. Immediate containment is recommended.",
    }),

    critical: Object.freeze({
        action: "urgent_containment",
        priority: "critical",
        requiresContainment: true,
        description:
            "Critical ransomware risk detected. Urgent investigation and containment are recommended.",
    }),
});

/**
 * Determines the risk level using the risk score.
 *
 * @param {number} riskScore
 * @returns {"low" | "medium" | "high" | "critical"}
 */
const getRiskLevel = (riskScore) => {
    if (
        typeof riskScore !== "number" ||
        !Number.isFinite(riskScore) ||
        riskScore < 0 ||
        riskScore > 100
    ) {
        throw new TypeError(
            "Risk score must be a finite number between 0 and 100."
        );
    }

    if (riskScore >= 80) {
        return "critical";
    }

    if (riskScore >= 60) {
        return "high";
    }

    if (riskScore >= 30) {
        return "medium";
    }

    return "low";
};

/**
 * Determines the appropriate security response.
 *
 * @param {Object} params
 * @param {number} params.riskScore
 * @returns {Object} Response decision
 */
const determineResponse = ({ riskScore } = {}) => {
    const riskLevel = getRiskLevel(riskScore);

    const policy = RESPONSE_POLICIES[riskLevel];

    return Object.freeze({
        riskScore,
        riskLevel,
        ...policy,
        evaluatedAt: new Date(),
    });
};

export default Object.freeze({
    getRiskLevel,
    determineResponse,
});