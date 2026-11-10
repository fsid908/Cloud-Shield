
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import File from "../src/models/file.model.js";
import fileService from "../src/services/file.service.js";
import fileActivityService from "../src/services/fileActivity.service.js";
import clamavService from "../src/services/clamav.service.js";
import securityEventService from "../src/services/securityEvent.service.js";

const createUploadedFile = () => {
    const buffer = Buffer.from("CloudShield upload test");

    return {
        originalname: "report.txt",
        mimetype: "text/plain",
        size: buffer.length,
        buffer,
    };
};

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

const mockFilesystem = (t, options = {}) => {
    const files = new Map();
    const unlinkedPaths = [];
    const renamedPaths = [];

    for (const [filePath, contents] of options.initialFiles ?? []) {
        files.set(filePath, Buffer.from(contents));
    }

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

    t.mock.method(fs, "rename", async (source, destination) => {
        if (!files.has(source)) {
            const error = new Error("File not found");
            error.code = "ENOENT";
            throw error;
        }

        if (files.has(destination)) {
            const error = new Error("Destination already exists");
            error.code = "EEXIST";
            throw error;
        }

        files.set(destination, files.get(source));
        files.delete(source);

        renamedPaths.push({ source, destination });
    });

    return {
        files,
        unlinkedPaths,
        renamedPaths,
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
    assert.equal(filesystem.files.size, 2);

    for (const contents of filesystem.files.values()) {
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

    assert.equal(filesystem.files.size, 0);
    assert.equal(filesystem.unlinkedPaths.length, 2);
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

    assert.equal(filesystem.files.size, 0);
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

    assert.equal(deletionAttempted, true);
    assert.equal(filesystem.files.size, 0);
});

test("preserves both files when database rollback fails", async (t) => {
    mockClamAV(t);

    const filesystem = mockFilesystem(t);
    const uploadedFile = createUploadedFile();

    const createdDocument = {
        _id: "test-file-id",
        originalName: uploadedFile.originalname,
    };

    t.mock.method(File, "create", async () => createdDocument);

    let deletionAttempted = false;

    t.mock.method(File, "deleteOne", async () => {
        deletionAttempted = true;
        throw new Error("Simulated database rollback failure");
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
            uploadedFile
        ),
        /Simulated activity logging failure/
    );

    assert.equal(deletionAttempted, true);
    assert.equal(filesystem.files.size, 2);

    for (const contents of filesystem.files.values()) {
        assert.deepEqual(
            contents,
            uploadedFile.buffer,
            "Preserved files must contain the original upload contents"
        );
    }

    assert.equal(filesystem.unlinkedPaths.length, 0);
});

test("quarantines an infected pending file and its backup", async (t) => {
    const infectedContents = Buffer.from("infected test content");
    const backupContents = Buffer.from("trusted backup content");

    const storedName = "pending-test.txt";
    const backupStoredName = "pending-backup.txt";

    const filePath = path.resolve(
        process.cwd(),
        "uploads",
        storedName
    );

    const backupPath = path.resolve(
        process.cwd(),
        "uploads",
        "backups",
        backupStoredName
    );

    const filesystem = mockFilesystem(t, {
        initialFiles: [
            [filePath, infectedContents],
            [backupPath, backupContents],
        ],
    });

    t.mock.method(clamavService, "scanBuffer", async (buffer) => {
        assert.deepEqual(buffer, infectedContents);

        return {
            status: "infected",
            result: "Eicar-Test-Signature",
        };
    });

    const file = {
        _id: "test-file-id",
        userId: "test-user-id",
        originalName: "test.txt",
        storedName,
        storagePath: path.join("uploads", storedName),
        backupStoredName,
        backupStoragePath: path.join(
            "uploads",
            "backups",
            backupStoredName
        ),
        backupHash: "test-backup-hash",
        status: "pending",
        integrityStatus: "intact",
        save: async () => file,
    };

    t.mock.method(File, "findOne", async (filter) => {
        assert.equal(filter._id, file._id);
        assert.equal(filter.userId, file.userId);

        return file;
    });

    let securityEvent;

    t.mock.method(
        securityEventService,
        "createSecurityEvent",
        async (event) => {
            securityEvent = event;
            return {};
        }
    );

    const result = await fileService.rescanPendingFile(
        file._id,
        file.userId
    );

    assert.equal(result, file);
    assert.equal(file.status, "quarantined");
    assert.equal(file.backupStoredName, null);
    assert.equal(file.backupStoragePath, null);
    assert.equal(file.backupHash, null);

    assert.ok(file.storedName.endsWith(".txt"));
    assert.equal(
    file.storagePath,
    path.join("uploads", "quarantine", file.storedName)
);

    assert.equal(filesystem.files.size, 2);
    assert.equal(filesystem.renamedPaths.length, 2);

    assert.equal(
        filesystem.renamedPaths.every(({ destination }) =>
            destination.includes(`${path.sep}quarantine${path.sep}`)
        ),
        true
    );

    assert.ok(securityEvent);
    assert.equal(securityEvent.eventType, "suspicious_activity");
    assert.equal(securityEvent.detectionType, "clamav_malware");
    assert.equal(securityEvent.riskScore, 90);
});
