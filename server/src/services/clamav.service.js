
import net from "node:net";

const CLAMAV_HOST = process.env.CLAMAV_HOST || "127.0.0.1";
const CLAMAV_PORT = Number(process.env.CLAMAV_PORT || 3310);
const SCAN_TIMEOUT = 15000;
const CHUNK_SIZE = 64 * 1024;

const scanBuffer = (buffer) => {
    if (!Buffer.isBuffer(buffer)) {
        return Promise.reject(new TypeError("A valid file buffer is required."));
    }

    return new Promise((resolve, reject) => {
        const socket = net.createConnection({
            host: CLAMAV_HOST,
            port: CLAMAV_PORT,
        });

        let response = "";
        let settled = false;

        const finish = (error, result) => {
            if (settled) return;
            settled = true;
            socket.destroy();

            if (error) reject(error);
            else resolve(result);
        };

        socket.setTimeout(SCAN_TIMEOUT);

        socket.on("connect", () => {
            socket.write("zINSTREAM\0");

            for (let offset = 0; offset < buffer.length; offset += CHUNK_SIZE) {
                const chunk = buffer.subarray(offset, offset + CHUNK_SIZE);
                const size = Buffer.alloc(4);
                size.writeUInt32BE(chunk.length);

                socket.write(size);
                socket.write(chunk);
            }

            socket.end(Buffer.alloc(4));
        });

        socket.on("data", (data) => {
            response += data.toString("utf8");

            if (response.includes("\0")) {
                const result = response.replace(/\0.*$/, "").trim();

                if (result.endsWith("OK")) {
                    finish(null, { status: "safe" });
                } else if (result.includes("FOUND")) {
                    finish(null, { status: "infected", result });
                } else {
                    finish(new Error(`ClamAV scan failed: ${result}`));
                }
            }
        });

        socket.on("timeout", () => {
            finish(new Error("ClamAV scan timed out."));
        });

        socket.on("error", (error) => {
            finish(new Error(`ClamAV connection failed: ${error.message}`));
        });

        socket.on("close", () => {
            if (!settled) {
                finish(new Error("ClamAV closed the connection unexpectedly."));
            }
        });
    });
};

export default { scanBuffer };
