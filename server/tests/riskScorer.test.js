import { describe, it } from "node:test";
import assert from "node:assert/strict";

import riskScorer from "../src/utils/riskScorer.js";

describe("riskScorer.calculateRiskScore", () => {
    it("should return zero risk when there is no activity", () => {
        const result = riskScorer.calculateRiskScore({
            uniqueFilesModified: 0,
            uniqueFilesDeleted: 0,
            totalEvents: 0,
            windowSeconds: 30,
        });

        assert.equal(result.score, 0);
        assert.deepEqual(result.reasons, []);
    });

    it("should assign 5 points for one modified file", () => {
        const result = riskScorer.calculateRiskScore({
            uniqueFilesModified: 1,
            windowSeconds: 30,
        });

        assert.equal(result.score, 5);
    });

    it("should assign 15 points for 3 modified files", () => {
        const result = riskScorer.calculateRiskScore({
            uniqueFilesModified: 3,
            windowSeconds: 30,
        });

        assert.equal(result.score, 15);
    });

    it("should assign 25 points for 6 to 10 modified files", () => {
        const result = riskScorer.calculateRiskScore({
            uniqueFilesModified: 8,
            windowSeconds: 60,
        });

        assert.equal(result.score, 25);
    });

    it("should assign 35 points for more than 10 modified files", () => {
        const result = riskScorer.calculateRiskScore({
            uniqueFilesModified: 11,
            windowSeconds: 60,
        });

        assert.equal(result.score, 35);
    });

    it("should calculate deletion risk independently", () => {
        const result = riskScorer.calculateRiskScore({
            uniqueFilesDeleted: 5,
            windowSeconds: 30,
        });

        assert.equal(result.score, 20);
    });

    it("should assign 30 points for 10 or more deleted files", () => {
        const result = riskScorer.calculateRiskScore({
            uniqueFilesDeleted: 10,
            windowSeconds: 60,
        });

        assert.equal(result.score, 30);
    });

    it("should add 10 frequency points for more than 3 events", () => {
        const result = riskScorer.calculateRiskScore({
            uniqueFilesModified: 1,
            totalEvents: 4,
            windowSeconds: 30,
        });

        assert.equal(result.score, 15);
    });

    it("should add 20 frequency points for more than 10 events", () => {
        const result = riskScorer.calculateRiskScore({
            uniqueFilesModified: 3,
            totalEvents: 11,
            windowSeconds: 30,
        });

        assert.equal(result.score, 35);
    });

    it("should not apply frequency risk outside 30 seconds", () => {
        const result = riskScorer.calculateRiskScore({
            uniqueFilesModified: 3,
            totalEvents: 11,
            windowSeconds: 60,
        });

        assert.equal(result.score, 15);
    });

    it("should add extension change risk", () => {
        const result = riskScorer.calculateRiskScore({
            extensionChanges: 5,
            windowSeconds: 30,
        });

        assert.equal(result.score, 10);
    });

    it("should add rename risk", () => {
        const result = riskScorer.calculateRiskScore({
            renames: 5,
            windowSeconds: 30,
        });

        assert.equal(result.score, 5);
    });

    it("should calculate high risk from combined indicators", () => {
        const result = riskScorer.calculateRiskScore({
            uniqueFilesModified: 11,
            totalEvents: 11,
            extensionChanges: 2,
            windowSeconds: 30,
        });

        assert.equal(result.score, 60);
        assert.equal(
            riskScorer.getRiskLevel(result.score),
            "high"
        );
    });

    it("should calculate critical risk from combined indicators", () => {
        const result = riskScorer.calculateRiskScore({
            uniqueFilesModified: 11,
            uniqueFilesDeleted: 10,
            totalEvents: 11,
            extensionChanges: 5,
            renames: 5,
            windowSeconds: 30,
        });

        assert.equal(result.score, 100);
        assert.equal(
            riskScorer.getRiskLevel(result.score),
            "critical"
        );
    });

    it("should reject negative activity counts", () => {
        assert.throws(
            () => riskScorer.calculateRiskScore({
                uniqueFilesModified: -1,
                windowSeconds: 30,
            }),
            TypeError
        );
    });

    it("should reject invalid risk scores", () => {
        assert.throws(
            () => riskScorer.getRiskLevel(101),
            TypeError
        );
    });
});

describe("riskScorer.getRiskLevel", () => {
    it("should classify scores below 30 as low", () => {
        assert.equal(riskScorer.getRiskLevel(0), "low");
        assert.equal(riskScorer.getRiskLevel(29), "low");
    });

    it("should classify scores from 30 to 59 as medium", () => {
        assert.equal(riskScorer.getRiskLevel(30), "medium");
        assert.equal(riskScorer.getRiskLevel(59), "medium");
    });

    it("should classify scores from 60 to 79 as high", () => {
        assert.equal(riskScorer.getRiskLevel(60), "high");
        assert.equal(riskScorer.getRiskLevel(79), "high");
    });

    it("should classify scores from 80 to 100 as critical", () => {
        assert.equal(riskScorer.getRiskLevel(80), "critical");
        assert.equal(riskScorer.getRiskLevel(100), "critical");
    });
});