import test from "node:test";
import assert from "node:assert/strict";

import responseEngine from "../src/services/responseEngine.service.js";

test("Response Engine", async (t) => {

    await t.test("should monitor low-risk activity", () => {
        const result = responseEngine.determineResponse({
            riskScore: 15,
        });

        assert.equal(result.riskLevel, "low");
        assert.equal(result.action, "monitor");
        assert.equal(result.priority, "low");
        assert.equal(result.requiresContainment, false);
    });

    await t.test("should generate an alert for medium risk", () => {
        const result = responseEngine.determineResponse({
            riskScore: 45,
        });

        assert.equal(result.riskLevel, "medium");
        assert.equal(result.action, "generate_alert");
        assert.equal(result.priority, "medium");
        assert.equal(result.requiresContainment, false);
    });

    await t.test("should recommend containment for high risk", () => {
        const result = responseEngine.determineResponse({
            riskScore: 65,
        });

        assert.equal(result.riskLevel, "high");
        assert.equal(result.action, "recommend_containment");
        assert.equal(result.priority, "high");
        assert.equal(result.requiresContainment, true);
    });

    await t.test("should recommend urgent containment for critical risk", () => {
        const result = responseEngine.determineResponse({
            riskScore: 90,
        });

        assert.equal(result.riskLevel, "critical");
        assert.equal(result.action, "urgent_containment");
        assert.equal(result.priority, "critical");
        assert.equal(result.requiresContainment, true);
    });

    await t.test("should handle risk-level boundaries correctly", () => {
        assert.equal(responseEngine.getRiskLevel(29), "low");
        assert.equal(responseEngine.getRiskLevel(30), "medium");

        assert.equal(responseEngine.getRiskLevel(59), "medium");
        assert.equal(responseEngine.getRiskLevel(60), "high");

        assert.equal(responseEngine.getRiskLevel(79), "high");
        assert.equal(responseEngine.getRiskLevel(80), "critical");
    });

    await t.test("should reject invalid risk scores", () => {
        const invalidScores = [
            -1,
            101,
            NaN,
            Infinity,
            -Infinity,
            "90",
            null,
        ];

        for (const riskScore of invalidScores) {
            assert.throws(
                () =>
                    responseEngine.determineResponse({
                        riskScore,
                    }),
                TypeError
            );
        }
    });

    await t.test("should reject missing risk score", () => {
        assert.throws(
            () => responseEngine.determineResponse({}),
            TypeError
        );
    });

    await t.test("should include evaluation timestamp", () => {
        const result = responseEngine.determineResponse({
            riskScore: 90,
        });

        assert.ok(result.evaluatedAt instanceof Date);

        assert.ok(
            !Number.isNaN(result.evaluatedAt.getTime())
        );
    });
});