import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import File from "../src/models/file.model.js";
import fileActivityService from "../src/services/fileActivity.service.js";
import recoveryService from "../src/services/recovery.service.js";

const UPLOAD_DIRECTORY = path.resolve(
    process.cwd(),
    "uploads"
);

const BACKUP_DIRECTORY = path.join(
    UPLOAD_DIRECTORY,
    "backups"
);

// Calculate SHA-256 to verify file contents.
const calculateHash = (content) => {
    return crypto
        .createHash("sha256")
        .update(content)
        .digest("hex");
};

// Create isolated files and a mocked file record for each test.
const createFixture = async (t, options = {}) => {
    await fs.mkdir(UPLOAD_DIRECTORY, {
        recursive: true,
    });

    await fs.mkdir(BACKUP_DIRECTORY, {
        recursive: true,
    });

    // Track existing recovery files so cleanup does not remove
    // files that existed before this test started.
    const initialEntries = new Set(
        await fs.readdir(UPLOAD_DIRECTORY)
    );

    const uniqueId = crypto.randomUUID();

    const userId = `test-user-${uniqueId}`;
    const fileId = `test-file-${uniqueId}`;

    const originalContents =
        options.originalContents ?? "trusted original content";

    const currentContents =
        options.currentContents ?? "modified current content";

    const originalBuffer = Buffer.from(originalContents);
    const currentBuffer = Buffer.from(currentContents);

    const storedName = `test-${uniqueId}.txt`;
    const backupStoredName = `backup-${uniqueId}.txt`;

    const currentFilePath = path.join(
        UPLOAD_DIRECTORY,
        storedName
    );

    const backupFilePath = path.join(
        BACKUP_DIRECTORY,
        backupStoredName
    );

    const expectedHash =
        options.expectedHash ?? calculateHash(originalBuffer);

    const backupHash =
        options.backupHash ?? calculateHash(originalBuffer);

    const file = {
        _id: fileId,
        userId,
        originalName: "document.txt",
        storedName,
        storagePath: path.join("uploads", storedName),
        backupStoredName,
        backupStoragePath: path.join(
            "uploads",
            "backups",
            backupStoredName
        ),
        size: originalBuffer.length,
        hash: expectedHash,
        backupHash,
        status: "safe",
        integrityStatus:
            options.integrityStatus ?? "modified",

        // Simulate the Mongoose document save operation.
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
            currentFilePath,
            currentBuffer
        );
    }

    if (options.createBackup !== false) {
        await fs.writeFile(
            backupFilePath,
            originalBuffer
        );
    }

    // Restore test-created files after every test, including failures.
    t.after(async () => {
        const pathsToRemove = [
            currentFilePath,
            backupFilePath,
        ];

        for (const filePath of pathsToRemove) {
            try {
                await fs.unlink(filePath);
            } catch (error) {
                if (error.code !== "ENOENT") {
                    throw error;
                }
            }
        }

        // Remove only recovery/rollback temporary files created
        // after this test's initial directory snapshot.
        const currentEntries = await fs.readdir(
            UPLOAD_DIRECTORY
        );

        for (const entry of currentEntries) {
            const isTemporaryFile =
                entry.startsWith(".recovery-") ||
                entry.startsWith(".rollback-");

            if (
                isTemporaryFile &&
                !initialEntries.has(entry)
            ) {
                try {
                    await fs.unlink(
                        path.join(UPLOAD_DIRECTORY, entry)
                    );
                } catch (error) {
                    if (error.code !== "ENOENT") {
                        throw error;
                    }
                }
            }
        }
    });

    return {
        file,
        fileId,
        userId,
        currentFilePath,
        backupFilePath,
        originalBuffer,
        currentBuffer,
        originalContents,
        currentContents,
        initialEntries,
    };
};

// Mock database lookup and activity recording.
// Node's test context restores these mocks after each test.
const mockDependencies = (
    t,
    findOneImplementation,
    activityCalls = []
) => {
    t.mock.method(
        File,
        "findOne",
        findOneImplementation
    );

    t.mock.method(
        fileActivityService,
        "recordFileActivity",
        async (activity) => {
            activityCalls.push(activity);
            return activity;
        }
    );

    return activityCalls;
};

// 1. Reject requests with missing file or user IDs.
test(
    "rejects recovery when file ID or user ID is missing",
    async (t) => {
        let lookupCalls = 0;

        mockDependencies(t, async () => {
            lookupCalls += 1;
            return null;
        });

        await assert.rejects(
            recoveryService.recoverFile(null, "test-user"),
            (error) => error.statusCode === 400
        );

        await assert.rejects(
            recoveryService.recoverFile("test-file", null),
            (error) => error.statusCode === 400
        );

        assert.equal(
            lookupCalls,
            0,
            "Database lookup must not run when IDs are missing"
        );
    }
);

// 2. Reject a file that does not exist or is not owned by the user.
test(
    "rejects recovery when the file does not exist",
    async (t) => {
        mockDependencies(t, async () => null);

        await assert.rejects(
            recoveryService.recoverFile(
                "missing-file",
                "test-user"
            ),
            (error) => error.statusCode === 404
        );
    }
);

// 3. Reject recovery when the trusted backup is unavailable.
test(
    "rejects recovery when the trusted backup is missing",
    async (t) => {
        const fixture = await createFixture(t, {
            createBackup: false,
        });

        mockDependencies(t, async () => fixture.file);

        await assert.rejects(
            recoveryService.recoverFile(
                fixture.fileId,
                fixture.userId
            ),
            (error) => error.statusCode === 404
        );

        // The current file must not be modified.
        const currentContents = await fs.readFile(
            fixture.currentFilePath,
            "utf8"
        );

        assert.equal(
            currentContents,
            fixture.currentContents
        );
    }
);

// 4. Reject a backup whose actual contents do not match its hash.
test(
    "rejects a backup whose SHA-256 hash does not match",
    async (t) => {
        const fixture = await createFixture(t, {
            backupHash: "invalid-sha256-hash",
        });

        mockDependencies(t, async () => fixture.file);

        await assert.rejects(
            recoveryService.recoverFile(
                fixture.fileId,
                fixture.userId
            ),
            (error) => error.statusCode === 409
        );

        // An untrusted backup must never replace the current file.
        const currentContents = await fs.readFile(
            fixture.currentFilePath,
            "utf8"
        );

        assert.equal(
            currentContents,
            fixture.currentContents
        );
    }
);

// 5. Preserve the current file and clean up after temporary
// recovery-file verification fails.
test(
    "preserves the current file and cleans up when temporary verification fails",
    async (t) => {
        const activityCalls = [];

        const fixture = await createFixture(t, {
            // The backup itself is valid, but it does not match
            // the expected original file hash.
            expectedHash: calculateHash(
                Buffer.from("different expected contents")
            ),
        });

        mockDependencies(
            t,
            async () => fixture.file,
            activityCalls
        );

        await assert.rejects(
            recoveryService.recoverFile(
                fixture.fileId,
                fixture.userId
            ),
            (error) => error.statusCode === 500
        );

        // The original current file must remain untouched.
        const currentContents = await fs.readFile(
            fixture.currentFilePath,
            "utf8"
        );

        assert.equal(
            currentContents,
            fixture.currentContents
        );

        // No new recovery temporary files should remain.
        const entriesAfterRecovery = await fs.readdir(
            UPLOAD_DIRECTORY
        );

        const leftoverRecoveryFiles =
            entriesAfterRecovery.filter(
                (entry) =>
                    entry.startsWith(".recovery-") &&
                    !fixture.initialEntries.has(entry)
            );

        assert.deepEqual(
            leftoverRecoveryFiles,
            [],
            "Temporary recovery files must be cleaned up"
        );

        assert.ok(
            activityCalls.some(
                (activity) =>
                    activity.activityType === "recovery_failed"
            ),
            "A failed recovery should record a failure activity"
        );
    }
);

// 6. Restore a valid backup and update the integrity status.
test(
    "restores a valid backup and marks the file intact",
    async (t) => {
        const activityCalls = [];

        const fixture = await createFixture(t);

        mockDependencies(
            t,
            async () => fixture.file,
            activityCalls
        );

        const result = await recoveryService.recoverFile(
            fixture.fileId,
            fixture.userId
        );

        const restoredContents = await fs.readFile(
            fixture.currentFilePath
        );

        assert.deepEqual(
            restoredContents,
            fixture.originalBuffer,
            "The trusted backup contents must be restored"
        );

        assert.equal(
            result.fileId,
            fixture.fileId
        );

        assert.equal(
            result.originalName,
            fixture.file.originalName
        );

        assert.equal(
            result.restoredHash,
            fixture.file.hash
        );

        assert.equal(
            result.integrityStatus,
            "intact"
        );

        assert.equal(
            fixture.file.integrityStatus,
            "intact"
        );

        assert.equal(
            fixture.file.saveCalled,
            true,
            "The updated document must be saved"
        );

        assert.ok(
            activityCalls.some(
                (activity) =>
                    activity.activityType === "recovered"
            ),
            "Successful recovery should be recorded"
        );
    }
);

// 7. Preserve the previous file contents when database persistence fails.
test(
    "preserves the previous file contents when database save fails",
    async (t) => {
        const activityCalls = [];

        const fixture = await createFixture(t, {
            saveError: new Error(
                "Simulated database write failure"
            ),
        });

        mockDependencies(
            t,
            async () => fixture.file,
            activityCalls
        );

        await assert.rejects(
            recoveryService.recoverFile(
                fixture.fileId,
                fixture.userId
            ),
            /Simulated database write failure/
        );

        // A failed database save must not leave the recovered
        // contents in place when rollback succeeds.
        const currentContents = await fs.readFile(
            fixture.currentFilePath
        );

        assert.deepEqual(
            currentContents,
            fixture.currentBuffer,
            "The previous file contents must be restored"
        );

        assert.equal(
            fixture.file.integrityStatus,
            "modified",
            "The in-memory integrity status must be restored"
        );

        assert.ok(
            activityCalls.some(
                (activity) =>
                    activity.activityType === "recovery_failed"
            ),
            "Failed persistence should record a failure activity"
        );
    }
);

test(
    "recovers a quarantined file and preserves the quarantined evidence",
    async (t) => {
        const userId = `test-user-${crypto.randomUUID()}`;
        const fileId = `test-file-${crypto.randomUUID()}`;

        const originalStoredName = `original-${crypto.randomUUID()}.txt`;
        const quarantineStoredName = `quarantine-${crypto.randomUUID()}.txt`;
        const backupStoredName = `backup-${crypto.randomUUID()}.txt`;

        const originalContents = Buffer.from(
            "trusted original file contents"
        );

        const suspiciousContents = Buffer.from(
            "suspicious modified file contents"
        );

        const expectedHash = calculateHash(originalContents);

        await fs.mkdir(UPLOAD_DIRECTORY, { recursive: true });
        await fs.mkdir(BACKUP_DIRECTORY, { recursive: true });
        await fs.mkdir(
            path.join(UPLOAD_DIRECTORY, "quarantine"),
            { recursive: true }
        );

        const originalFilePath = path.join(
            UPLOAD_DIRECTORY,
            originalStoredName
        );

        const quarantineFilePath = path.join(
            UPLOAD_DIRECTORY,
            "quarantine",
            quarantineStoredName
        );

        const backupFilePath = path.join(
            BACKUP_DIRECTORY,
            backupStoredName
        );

        await fs.writeFile(
            quarantineFilePath,
            suspiciousContents
        );

        await fs.writeFile(
            backupFilePath,
            originalContents
        );

        const file = {
            _id: fileId,
            userId,
            originalName: "document.txt",

            storedName: quarantineStoredName,

            storagePath: path.join(
                "uploads",
                "quarantine",
                quarantineStoredName
            ),

            originalStoredName,
            quarantineStoredName,

            backupStoredName,

            backupStoragePath: path.join(
                "uploads",
                "backups",
                backupStoredName
            ),

            backupHash: expectedHash,
            hash: expectedHash,

            status: "quarantined",
            integrityStatus: "unavailable",

            save: async function () {
                this.saveCalled = true;
                return this;
            },
        };

        const activityCalls = [];

        t.mock.method(
            File,
            "findOne",
            async () => file
        );

        t.mock.method(
            fileActivityService,
            "recordFileActivity",
            async (activity) => {
                activityCalls.push(activity);
                return activity;
            }
        );

        t.after(async () => {
            for (const filePath of [
                originalFilePath,
                quarantineFilePath,
                backupFilePath,
            ]) {
                try {
                    await fs.unlink(filePath);
                } catch (error) {
                    if (error.code !== "ENOENT") {
                        throw error;
                    }
                }
            }
        });

        const result = await recoveryService.recoverFile(
            fileId,
            userId
        );

        // Verify that the original file was restored.
        const restoredContents = await fs.readFile(
            originalFilePath
        );

        assert.deepEqual(
            restoredContents,
            originalContents
        );

        // Verify that quarantined evidence still exists.
        const preservedEvidence = await fs.readFile(
            quarantineFilePath
        );

        assert.deepEqual(
            preservedEvidence,
            suspiciousContents
        );

        // Verify database metadata.
        assert.equal(file.status, "safe");
        assert.equal(file.integrityStatus, "intact");
        assert.equal(file.storedName, originalStoredName);

        assert.equal(
            file.originalStoredName,
            originalStoredName
        );

        assert.equal(
            file.quarantineStoredName,
            quarantineStoredName
        );

        assert.equal(file.saveCalled, true);

        // Verify the recovery result.
        assert.equal(result.fileId, fileId);
        assert.equal(result.restoredHash, expectedHash);
        assert.equal(result.integrityStatus, "intact");

        // Verify successful recovery activity.
        assert.ok(
            activityCalls.some(
                (activity) => activity.activityType === "recovered"
            )
        );
    }
);