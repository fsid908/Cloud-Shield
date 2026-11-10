import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import File from "../src/models/file.model.js";
import containmentService from "../src/services/containment.service.js";
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

// Create isolated files and a mock database document.
const createFixture = async (t, options = {}) => {
    await fs.mkdir(UPLOAD_DIRECTORY, {
        recursive: true,
    });

    await fs.mkdir(BACKUP_DIRECTORY, {
        recursive: true,
    });

    await fs.mkdir(QUARANTINE_DIRECTORY, {
        recursive: true,
    });

    const uniqueId = crypto.randomUUID();

    const userId = `test-user-${uniqueId}`;
    const fileId = `test-file-${uniqueId}`;

    const storedName = `test-${uniqueId}.txt`;
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
        "Suspicious file content"
    );

    const trustedBackupContents = Buffer.from(
        "Trusted original backup content"
    );

    const file = {
        _id: fileId,
        userId,

        originalName: "document.txt",

        storedName,

        storagePath: path.join(
            "uploads",
            storedName
        ),

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

        status: options.status ?? "safe",
        integrityStatus: "intact",

        save: async function () {
            if (options.saveError) {
                throw options.saveError;
            }

            this.saveCalled = true;

            return this;
        },
    };

    if (options.createCurrent !== false) {
        await fs.writeFile(
            currentPath,
            originalContents
        );
    }

    if (options.createBackup !== false) {
        await fs.writeFile(
            backupPath,
            trustedBackupContents
        );
    }

    // Remove only the files created by this test.
    t.after(async () => {
        await fs.rm(currentPath, {
            force: true,
        });

        await fs.rm(backupPath, {
            force: true,
        });

        // The service updates storedName after successful isolation.
        if (file.storedName !== storedName) {
            const quarantinedPath = path.join(
                QUARANTINE_DIRECTORY,
                file.storedName
            );

            await fs.rm(quarantinedPath, {
                force: true,
            });
        }
    });

    t.mock.method(
        File,
        "findOne",
        async (filter) => {
            assert.deepEqual(filter, {
                _id: fileId,
                userId,
            });

            if (options.notFound) {
                return null;
            }

            return file;
        }
    );

    return {
        userId,
        fileId,
        file,
        currentPath,
        backupPath,
        originalContents,
        trustedBackupContents,
    };
};

const validContainmentInput = (fixture, overrides = {}) => ({
    userId: fixture.userId,
    fileId: fixture.fileId,
    riskScore: 85,
    riskLevel: "critical",
    episodeId: "test-episode-123",
    reason: "Suspicious ransomware activity detected.",
    ...overrides,
});

test(
    "isolates a high-risk file and preserves its trusted backup",
    async (t) => {
        const fixture = await createFixture(t);

        let recordedEvent = null;

        t.mock.method(
            securityEventService,
            "createSecurityEvent",
            async (event) => {
                recordedEvent = event;
                return event;
            }
        );

        const result = await containmentService.containFile(
            validContainmentInput(fixture, {
                riskScore: 70,
                riskLevel: "high",
            })
        );

        assert.equal(result.status, "quarantined");

        assert.equal(
            fixture.file.status,
            "quarantined"
        );

        assert.equal(
            fixture.file.integrityStatus,
            "unavailable"
        );
        assert.equal(
            fixture.file.originalStoredName,
            path.basename(fixture.currentPath),
            "Original stored filename must be preserved"
        );

        assert.equal(
            fixture.file.quarantineStoredName,
            result.quarantinedStoredName,
            "Quarantine filename must be recorded"
        );


        assert.equal(
            await fs.access(fixture.currentPath).then(
                () => true,
                () => false
            ),
            false
        );

        const quarantinedPath = path.join(
            QUARANTINE_DIRECTORY,
            result.quarantinedStoredName
        );

        const quarantinedContents = await fs.readFile(
            quarantinedPath
        );

        assert.deepEqual(
            quarantinedContents,
            fixture.originalContents
        );

        const backupContents = await fs.readFile(
            fixture.backupPath
        );

        assert.deepEqual(
            backupContents,
            fixture.trustedBackupContents
        );

        assert.equal(
            fixture.file.backupStoredName,
            path.basename(fixture.backupPath)
        );

        assert.equal(
            fixture.file.backupHash !== null,
            true
        );

        assert.equal(
            recordedEvent.detectionType,
            "automatic_containment"
        );

        assert.equal(
            recordedEvent.metadata.backupPreserved,
            true
        );
    }
);

test(
    "rejects containment for low-risk activity",
    async (t) => {
        const fixture = await createFixture(t);

        await assert.rejects(
            containmentService.containFile(
                validContainmentInput(fixture, {
                    riskScore: 20,
                    riskLevel: "low",
                })
            ),
            {
                message:
                    "Containment is only allowed for high or critical risk.",
                statusCode: 403,
            }
        );

        assert.equal(
            await fs.access(fixture.currentPath).then(
                () => true,
                () => false
            ),
            true
        );
    }
);

test(
    "rejects containment when the file does not belong to the user",
    async (t) => {
        const fixture = await createFixture(t, {
            notFound: true,
        });

        await assert.rejects(
            containmentService.containFile(
                validContainmentInput(fixture)
            ),
            {
                message: "File not found or access denied.",
                statusCode: 404,
            }
        );
    }
);

test(
    "does not move a file that is already quarantined",
    async (t) => {
        const fixture = await createFixture(t, {
            status: "quarantined",
        });

        const result = await containmentService.containFile(
            validContainmentInput(fixture)
        );

        assert.equal(
            result.status,
            "already_quarantined"
        );

        assert.equal(
            await fs.access(fixture.currentPath).then(
                () => true,
                () => false
            ),
            true
        );
    }
);

test(
    "skips containment when the original file is missing",
    async (t) => {
        const fixture = await createFixture(t, {
            createCurrent: false,
        });

        const result = await containmentService.containFile(
            validContainmentInput(fixture)
        );

        assert.equal(result.status, "skipped");

        assert.equal(
            result.reason,
            "Original file is missing."
        );
    }
);

test(
    "restores the original file when database saving fails",
    async (t) => {
        const saveError = new Error(
            "Simulated database save failure"
        );

        const fixture = await createFixture(t, {
            saveError,
        });

        await assert.rejects(
            containmentService.containFile(
                validContainmentInput(fixture)
            ),
            (error) => error === saveError
        );

        const originalExists = await fs.access(
            fixture.currentPath
        ).then(
            () => true,
            () => false
        );

        assert.equal(
            originalExists,
            true,
            "Original file should be restored"
        );

        assert.equal(
            fixture.file.status,
            "safe"
        );

        assert.equal(
            fixture.file.storedName,
            path.basename(fixture.currentPath)
        );
    }
);

test(
    "keeps the file quarantined if security event logging fails",
    async (t) => {
        const fixture = await createFixture(t);

        t.mock.method(
            securityEventService,
            "createSecurityEvent",
            async () => {
                throw new Error(
                    "Simulated security event database failure"
                );
            }
        );

        await assert.rejects(
            containmentService.containFile(
                validContainmentInput(fixture)
            ),
            {
                message:
                    "File was quarantined, but the containment security event could not be recorded. Audit investigation is required.",
                statusCode: 500,
            }
        );

        assert.equal(
            fixture.file.status,
            "quarantined"
        );

        const quarantinedPath = path.join(
            QUARANTINE_DIRECTORY,
            fixture.file.storedName
        );

        assert.equal(
            await fs.access(quarantinedPath).then(
                () => true,
                () => false
            ),
            true
        );
    }
);

test(
    "rejects invalid risk scores",
    async (t) => {
        const fixture = await createFixture(t);

        await assert.rejects(
            containmentService.containFile(
                validContainmentInput(fixture, {
                    riskScore: 150,
                })
            ),
            {
                message:
                    "Risk score must be between 0 and 100.",
                statusCode: 400,
            }
        );
    }
);