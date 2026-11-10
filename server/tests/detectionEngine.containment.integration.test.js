import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import File from "../src/models/file.model.js";
import activityAnalysisService from "../src/services/activityAnalysis.service.js";
import detectionEngine from "../src/services/detectionEngine.service.js";
import securityEventService from "../src/services/securityEvent.service.js";

const UPLOAD_DIRECTORY = path.resolve(
    process.cwd(),
    "uploads"
);

const BACKUP_DIRECTORY = path.join(
    UPLOAD_DIRECTORY,
    "backups"
);

const QUARANTINE_DIRECTORY = path.join(
    UPLOAD_DIRECTORY,
    "quarantine"
);

const createFileFixtures = async (t, count) => {
    await fs.mkdir(UPLOAD_DIRECTORY, { recursive: true });
    await fs.mkdir(BACKUP_DIRECTORY, { recursive: true });
    await fs.mkdir(QUARANTINE_DIRECTORY, { recursive: true });

    const userId = crypto.randomBytes(12).toString("hex");

    const fixtures = [];

    for (let index = 0; index < count; index++) {
        const fileId = crypto.randomBytes(12).toString("hex");
        const uniqueId = crypto.randomUUID();

        const storedName = `integration-${uniqueId}.txt`;
        const backupStoredName = `backup-${uniqueId}.txt`;

        const currentPath = path.join(
            UPLOAD_DIRECTORY,
            storedName
        );

        const backupPath = path.join(
            BACKUP_DIRECTORY,
            backupStoredName
        );

        const originalContents = Buffer.from(
            `Suspicious content ${index}`
        );

        const trustedBackupContents = Buffer.from(
            `Trusted backup ${index}`
        );

        const file = {
            _id: fileId,
            userId,
            originalName: `document-${index}.txt`,

            storedName,
            storagePath: path.join("uploads", storedName),

            backupStoredName,
            backupStoragePath: path.join(
                "uploads",
                "backups",
                backupStoredName
            ),

            backupHash: crypto
                .createHash("sha256")
                .update(trustedBackupContents)
                .digest("hex"),

            status: "safe",
            integrityStatus: "intact",

            save: async function () {
                return this;
            },
        };

        await fs.writeFile(currentPath, originalContents);
        await fs.writeFile(backupPath, trustedBackupContents);

        fixtures.push({
            file,
            currentPath,
            backupPath,
            originalContents,
            trustedBackupContents,
        });
    }

    const fileMap = new Map(
        fixtures.map(({ file }) => [
            String(file._id),
            file,
        ])
    );

    t.mock.method(
        File,
        "findOne",
        async ({ _id, userId: requestedUserId }) => {
            const file = fileMap.get(String(_id));

            if (!file || file.userId !== requestedUserId) {
                return null;
            }

            return file;
        }
    );

    t.after(async () => {
        for (const fixture of fixtures) {
            await fs.rm(fixture.currentPath, {
                force: true,
            });

            await fs.rm(fixture.backupPath, {
                force: true,
            });

            const possibleQuarantinePath = path.join(
                QUARANTINE_DIRECTORY,
                fixture.file.storedName
            );

            await fs.rm(possibleQuarantinePath, {
                force: true,
            });
        }
    });

    return {
        userId,
        fixtures,
    };
};

const createActivity = (fileId, index, activityType) => ({
    _id: `activity-${index}`,
    fileId,
    activityType,
});

test(
    "medium-risk activity generates alerts without quarantining files",
    async (t) => {
        const fixture = await createFileFixtures(t, 6);

        const activities = fixture.fixtures.map(
            ({ file }, index) =>
                createActivity(
                    file._id,
                    index,
                    "modified"
                )
        );

        t.mock.method(
            activityAnalysisService,
            "analyzeRecentActivity",
            async () => ({
                windowSeconds: 30,
                totalActivities: 6,
                uniqueFiles: 6,
                modifications: 6,
                deletions: 0,
                renames: 0,
                extensionChanges: 0,
                activities,
            })
        );

        t.mock.method(
            securityEventService,
            "createSecurityEvent",
            async (event) => event
        );

        const findOneMock = File.findOne;

        const result =
            await detectionEngine.detectSuspiciousActivity(
                fixture.userId
            );

        assert.equal(result.riskLevel, "medium");
        assert.equal(result.responseDecision.action, "generate_alert");
        assert.equal(result.responseDecision.requiresContainment, false);

        assert.equal(result.containment, null);

        assert.equal(findOneMock.mock.callCount(), 0);

        for (const item of fixture.fixtures) {
            assert.equal(item.file.status, "safe");

            await fs.access(item.currentPath);
            await fs.access(item.backupPath);
        }
    }
);

test(
    "high-risk activity automatically quarantines affected files",
    async (t) => {
        const fixture = await createFileFixtures(t, 16);

        const activities = [];

        // Six unique file modifications.
        fixture.fixtures.slice(0, 6).forEach(
            ({ file }, index) => {
                activities.push(
                    createActivity(
                        file._id,
                        index,
                        "modified"
                    )
                );
            }
        );

        // Ten unique file deletions.
        fixture.fixtures.slice(6).forEach(
            ({ file }, index) => {
                activities.push(
                    createActivity(
                        file._id,
                        index + 6,
                        "deleted"
                    )
                );
            }
        );

        t.mock.method(
            activityAnalysisService,
            "analyzeRecentActivity",
            async () => ({
                windowSeconds: 30,
                totalActivities: 16,
                uniqueFiles: 16,
                modifications: 6,
                deletions: 10,
                renames: 0,
                extensionChanges: 0,
                activities,
            })
        );

        t.mock.method(
            securityEventService,
            "createSecurityEvent",
            async (event) => event
        );

        const result =
            await detectionEngine.detectSuspiciousActivity(
                fixture.userId
            );

        assert.equal(result.riskLevel, "high");
        assert.equal(result.responseDecision.requiresContainment, true);

        assert.ok(result.containment);

        assert.equal(result.containment.totalFiles, 16);
        assert.equal(result.containment.quarantinedCount, 16);

        for (const item of fixture.fixtures) {
            assert.equal(item.file.status, "quarantined");

            assert.equal(
                item.file.integrityStatus,
                "unavailable"
            );

            await assert.rejects(
                fs.access(item.currentPath),
                { code: "ENOENT" }
            );

            const quarantinedPath = path.join(
                QUARANTINE_DIRECTORY,
                item.file.storedName
            );

            const quarantinedContents = await fs.readFile(
                quarantinedPath
            );

            assert.deepEqual(
                quarantinedContents,
                item.originalContents
            );

            const backupContents = await fs.readFile(
                item.backupPath
            );

            assert.deepEqual(
                backupContents,
                item.trustedBackupContents
            );
        }
    }
);