import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import File from "../src/models/file.model.js";
import fileService from "../src/services/file.service.js";
import fileActivityService from "../src/services/fileActivity.service.js";
import clamavService from "../src/services/clamav.service.js";

/**
 * Creates a valid plain-text upload for testing.
 * The file validator accepts text/plain when no binary
 * file signature is detected.
 */
const createUploadedFile = () => {
    const buffer = Buffer.from("CloudShield upload test");

    return {
        originalname: "report.txt",
        mimetype: "text/plain",
        size: buffer.length,
        buffer,
    };
};

/**
 * Mocks ClamAV to simulate a clean file scan.
 * Unit tests should not depend on an external ClamAV daemon.
 */
const mockClamAV = (t) => {
    t.mock.method(
        clamavService,
        "scanBuffer",
        async (buffer) => {
            assert.ok(Buffer.isBuffer(buffer));

            return {
                status: "safe",
            };
        }
    );
};

/**
 * Mocks filesystem operations so tests never need to write
 * to the application's real uploads directory.
 *
 * The in-memory map simulates files created by the service.
 */
const mockFilesystem = (t, options = {}) => {
    const files = new Map();
    const unlinkedPaths = [];

    t.mock.method(fs, "mkdir", async () => undefined);

    t.mock.method(fs, "open", async (filePath, flags, mode) => {
        assert.equal(flags, "wx");
        assert.equal(mode, 0o600);

        return {
            writeFile: async (buffer) => {
                const isBackup = filePath
                    .split(path.sep)
                    .includes("backups");

                if (options.failBackupWrite && isBackup) {
                    // Simulate a partial write before failure.
                    files.set(
                        filePath,
                        Buffer.from(buffer).subarray(0, 4)
                    );

                    throw new Error("Simulated backup write failure");
                }

                files.set(filePath, Buffer.from(buffer));
            },

            close: async () => undefined,
        };
    });

    t.mock.method(fs, "readFile", async (filePath) => {
        if (!files.has(filePath)) {
            const error = new Error("File not found");
            error.code = "ENOENT";
            throw error;
        }

        return files.get(filePath);
    });

    t.mock.method(fs, "unlink", async (filePath) => {
        unlinkedPaths.push(filePath);

        if (!files.has(filePath)) {
            const error = new Error("File not found");
            error.code = "ENOENT";
            throw error;
        }

        files.delete(filePath);
    });

    return {
        files,
        unlinkedPaths,
    };
};

test("creates the current file, trusted backup, metadata, and activity", async (t) => {
    mockClamAV(t);

    const filesystem = mockFilesystem(t);
    const uploadedFile = createUploadedFile();

    const userId = "test-user-id";

    const createdDocument = {
        _id: "test-file-id",
        originalName: uploadedFile.originalname,
    };

    t.mock.method(File, "create", async (document) => {
        assert.equal(document.userId, userId);
        assert.equal(document.originalName, "report.txt");
        assert.equal(document.hash, document.backupHash);

        return createdDocument;
    });

    t.mock.method(
        fileActivityService,
        "recordFileActivity",
        async () => ({})
    );

    const result = await fileService.createFile(
        userId,
        uploadedFile
    );

    assert.equal(result, createdDocument);

    assert.equal(
        filesystem.files.size,
        2,
        "Both current file and backup should exist"
    );

    const storedContents = [...filesystem.files.values()];

    for (const contents of storedContents) {
        assert.deepEqual(contents, uploadedFile.buffer);
    }
});

test("cleans up the current file and partial backup when backup writing fails", async (t) => {
    mockClamAV(t);

    const filesystem = mockFilesystem(t, {
        failBackupWrite: true,
    });

    const uploadedFile = createUploadedFile();

    t.mock.method(File, "create", async () => {
        assert.fail("Database record must not be created");
    });

    await assert.rejects(
        fileService.createFile("test-user-id", uploadedFile),
        /Simulated backup write failure/
    );

    assert.equal(
        filesystem.files.size,
        0,
        "Files created by the failed upload should be removed"
    );

    assert.equal(
        filesystem.unlinkedPaths.length,
        2,
        "Cleanup should attempt to remove both owned files"
    );
});

test("cleans up both files when database record creation fails", async (t) => {
    mockClamAV(t);

    const filesystem = mockFilesystem(t);

    t.mock.method(File, "create", async () => {
        throw new Error("Simulated database creation failure");
    });

    await assert.rejects(
        fileService.createFile(
            "test-user-id",
            createUploadedFile()
        ),
        /Simulated database creation failure/
    );

    assert.equal(
        filesystem.files.size,
        0,
        "Both files should be removed after database creation fails"
    );
});

test("attempts database rollback when activity logging fails", async (t) => {
    mockClamAV(t);

    const filesystem = mockFilesystem(t);

    const createdDocument = {
        _id: "test-file-id",
        originalName: "report.txt",
    };

    t.mock.method(File, "create", async () => createdDocument);

    let deletionAttempted = false;

    t.mock.method(File, "deleteOne", async (filter) => {
        deletionAttempted = true;

        assert.equal(filter._id, createdDocument._id);
        assert.equal(filter.userId, "test-user-id");

        return {
            deletedCount: 1,
        };
    });

    t.mock.method(
        fileActivityService,
        "recordFileActivity",
        async () => {
            throw new Error("Simulated activity logging failure");
        }
    );

    await assert.rejects(
        fileService.createFile(
            "test-user-id",
            createUploadedFile()
        ),
        /Simulated activity logging failure/
    );

    assert.equal(
        deletionAttempted,
        true,
        "The service should attempt to roll back the database record"
    );

    assert.equal(
        filesystem.files.size,
        0,
        "Owned files should be removed after successful database rollback"
    );
});

test(
    "preserves both files when database rollback fails",
    async (t) => {
        mockClamAV(t);

        const filesystem = mockFilesystem(t);

        const uploadedFile = createUploadedFile();

        const createdDocument = {
            _id: "test-file-id",
            originalName: uploadedFile.originalname,
        };

        // Simulate successful creation of the database record.
        t.mock.method(File, "create", async () => createdDocument);

        let deletionAttempted = false;

        // Simulate a database failure during rollback.
        t.mock.method(File, "deleteOne", async () => {
            deletionAttempted = true;

            throw new Error("Simulated database rollback failure");
        });

        // Simulate failure after the files and database record exist.
        t.mock.method(
            fileActivityService,
            "recordFileActivity",
            async () => {
                throw new Error("Simulated activity logging failure");
            }
        );

        // The original activity logging error must be preserved.
        await assert.rejects(
            fileService.createFile(
                "test-user-id",
                uploadedFile
            ),
            /Simulated activity logging failure/
        );

        // Verify that the service attempted database rollback.
        assert.equal(
            deletionAttempted,
            true,
            "The service should attempt database rollback"
        );

        // Both the current file and backup must remain available.
        assert.equal(
            filesystem.files.size,
            2,
            "Both files must be preserved when database rollback fails"
        );

        // Verify that the original file contents remain intact.
        for (const contents of filesystem.files.values()) {
            assert.deepEqual(
                contents,
                uploadedFile.buffer,
                "Preserved files must contain the original upload contents"
            );
        }

        // No physical file should have been deleted.
        assert.equal(
            filesystem.unlinkedPaths.length,
            0,
            "The service must not delete files when rollback fails"
        );
    }
);