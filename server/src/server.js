import app from "./app.js";
import env from "./config/env.js";
import connectDB from "./config/db.js";
import fileMonitor from "./services/fileMonitor.service.js";

let httpServer;
let isShuttingDown = false;

// Close application resources during shutdown.
const shutdown = async (signal) => {
  if (isShuttingDown) {
    return;
  }

  isShuttingDown = true;
  console.log(`Received ${signal}. Shutting down Cloud-Shield...`);

  try {
    // Stop accepting new HTTP connections.
    if (httpServer) {
      await new Promise((resolve, reject) => {
        httpServer.close((error) => {
          if (error) {
            reject(error);
            return;
          }

          resolve();
        });
      });
    }

    // Release filesystem watcher resources.
    await fileMonitor.stop();

    console.log("Cloud-Shield shut down successfully.");
    process.exitCode = 0;
  } catch (error) {
    console.error("Cloud-Shield shutdown failed:", error);
    process.exitCode = 1;
  }
};

// Initialize dependencies before accepting requests.
const startServer = async () => {
  try {
    // Connect to MongoDB first.
    await connectDB();

    // Start monitoring only after the database is ready.
    await fileMonitor.start();

    // Start Express after initialization succeeds.
    httpServer = app.listen(env.PORT, () => {
      console.log(
        `Cloud-Shield Server is running on http://localhost:${env.PORT}`
      );
      console.log(`Environment: ${env.NODE_ENV}`);
    });

    // Handle normal process termination.
    process.once("SIGINT", () => {
      void shutdown("SIGINT");
    });

    process.once("SIGTERM", () => {
      void shutdown("SIGTERM");
    });
  } catch (error) {
    console.error("Failed to start Cloud-Shield.");
    console.error(error);

    try {
      await fileMonitor.stop();
    } catch (shutdownError) {
      console.error(
        "Failed to clean up the filesystem monitor:",
        shutdownError
      );
    }

    process.exitCode = 1;
  }
};

startServer();