import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createFileMonitor } from "../src/services/fileMonitor.service.js";

const hash = (contents) =>
    crypto.createHash("sha256").update(contents).digest("hex");

const wait = (milliseconds) =>
    new Promise((resolve) => setTimeout(resolve, milliseconds));

class FakeWatcher extends EventEmitter {
    closed = false;

    async close() {
        this.closed = true;
    }
}

const createHarness = async (t, { contents = "trusted content" } = {}) => {
    const tempDirectory = await fs.mkdtemp(
        path.join(os.tmpdir(), "cloud-shield-monitor-")
    );

    const uploadsDirectory = path.join(tempDirectory, "uploads");
    const backupsDirectory = path.join(uploadsDirectory, "backups");

    await fs.mkdir(backupsDirectory, { recursive: true });

    t.after(async () => {
        await fs.rm(tempDirectory, { recursive: true, force: true });
    });

    const trackedPath = path.join(uploadsDirectory, "tracked-file.txt");

    await fs.writeFile(trackedPath, contents);

    const trackedFile = {
        _id: "file-1",
        userId: "user-1",
        storedName: "tracked-file.txt",
        originalName: "report.txt",
        hash: hash(Buffer.from("trusted content")),
        integrityStatus: "intact",
    };

    const events = [];
    const statusUpdates = [];
    let watcher;
    let watcherCreations = 0;

    const monitor = createFileMonitor({
        uploadsDirectory,
        debounceMs: 20,
        deleteGraceMs: 50,
        watchFactory: () => {
            watcherCreations += 1;
            watcher = new FakeWatcher();

            // Chokidar emits ready asynchronously after attaching listeners.
            setImmediate(() => watcher.emit("ready"));
            return watcher;
        },
        findTrackedFile: async (storedName) =>
            storedName === trackedFile.storedName ? trackedFile : null,
        readFile: fs.readFile,
        setIntegrityStatus: async (file, status) => {
            statusUpdates.push({ fileId: file._id, status });
            file.integrityStatus = status;
        },
        createIntegrityEvent: async (event) => {
            events.push(event);
            return event;
        },
        logger: {
            info() {},
            warn() {},
            error() {},
        },
    });

    return {
        monitor,
        trackedPath,
        trackedFile,
        events,
        statusUpdates,
        get watcher() {
            return watcher;
        },
        get watcherCreations() {
            return watcherCreations;
        },
        uploadsDirectory,
        backupsDirectory,
    };
};

test("starts a single watcher and stops it safely more than once", async (t) => {
    const harness = await createHarness(t);

    await harness.monitor.start();
    await harness.monitor.start();

    assert.equal(harness.watcherCreations, 1);

    await harness.monitor.stop();
    await harness.monitor.stop();

    assert.equal(harness.watcher.closed, true);
});

test("does not raise an integrity event when file content matches the trusted hash", async (t) => {
    const harness = await createHarness(t);

    await harness.monitor.start();
    harness.watcher.emit("change", harness.trackedPath);

    await wait(100);

    assert.equal(harness.events.length, 0);

    await harness.monitor.stop();
});

test("records an integrity violation when tracked file content changes", async (t) => {
    const harness = await createHarness(t, {
        contents: "changed content",
    });

    await harness.monitor.start();
    harness.watcher.emit("change", harness.trackedPath);

    await wait(100);

    assert.equal(harness.events.length, 1);
    assert.equal(harness.events[0].eventType, "integrity_violation");
    assert.equal(harness.events[0].currentHash, hash(Buffer.from("changed content")));
    assert.equal(harness.trackedFile.integrityStatus, "modified");

    await harness.monitor.stop();
});

test("debounces duplicate filesystem notifications for the same content", async (t) => {
    const harness = await createHarness(t, {
        contents: "changed content",
    });

    await harness.monitor.start();
    harness.watcher.emit("change", harness.trackedPath);
    harness.watcher.emit("change", harness.trackedPath);
    harness.watcher.emit("change", harness.trackedPath);

    await wait(120);

    assert.equal(harness.events.length, 1);

    await harness.monitor.stop();
});

test("reports a tracked file that remains missing after the grace period", async (t) => {
    const harness = await createHarness(t);

    await harness.monitor.start();
    await fs.unlink(harness.trackedPath);

    harness.watcher.emit("unlink", harness.trackedPath);

    await wait(150);

    assert.equal(harness.events.length, 1);
    assert.equal(harness.events[0].currentHash, "missing");
    assert.equal(harness.trackedFile.integrityStatus, "unavailable");

    await harness.monitor.stop();
});

test("ignores untracked files and files inside the backups directory", async (t) => {
    const harness = await createHarness(t);

    const backupPath = path.join(harness.backupsDirectory, "backup.txt");
    const untrackedPath = path.join(harness.uploadsDirectory, "untracked.txt");

    await fs.writeFile(backupPath, "backup");
    await fs.writeFile(untrackedPath, "untracked");

    await harness.monitor.start();

    harness.watcher.emit("change", backupPath);
    harness.watcher.emit("change", untrackedPath);

    await wait(100);

    assert.equal(harness.events.length, 0);

    await harness.monitor.stop();
});