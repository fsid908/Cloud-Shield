# Cloud-Shield System Architecture

## 1. Overview

Cloud-Shield is a cloud-oriented file integrity monitoring and security event analysis application.

The system combines a React-based frontend, an Express.js backend, MongoDB persistence, and filesystem monitoring to track stored files and identify suspicious activity.

Its primary capabilities include:

- User authentication and session management.
- File upload and storage.
- File integrity verification using SHA-256 hashes.
- File activity tracking.
- Suspicious activity analysis.
- Security event persistence and history.
- Backup-based file recovery.
- A dashboard for presenting security information.

The application separates HTTP handling, business logic, database models, and filesystem operations into different modules.

This separation improves maintainability, testability, and the ability to evolve individual components independently.

---

## 2. High-Level Architecture

```text
+------------------------------------------------------+
|                    React Frontend                    |
|                                                      |
| App.jsx                                              |
| Sidebar | Topbar | MetricCard | SecurityChart        |
| SecurityEventsTable | BackupHealth                   |
+---------------------------+--------------------------+
                            |
                            | HTTP requests
                            | Cookies / credentials
                            v
+------------------------------------------------------+
|                 Express Backend                      |
|                                                      |
| app.js                                               |
|                                                      |
| Helmet | Morgan | Body Parsers | Cookie Parser       |
| CORS | Not Found Handler | Error Handler             |
|                                                      |
|                    /api Routes                       |
+---------------------------+--------------------------+
                            |
                            v
+------------------------------------------------------+
|              Middleware and Controllers              |
|                                                      |
| Authentication | Authorization | Validation         |
| Upload Handling | Request / Response Processing      |
+---------------------------+--------------------------+
                            |
                            v
+------------------------------------------------------+
|                   Service Layer                      |
|                                                      |
| Authentication | File Management | Integrity         |
| File Monitoring | Activity Tracking | Detection      |
| Security Events | Recovery | Health                  |
+----------------------+-------------------------------+
                       |
             +---------+----------+
             |                    |
             v                    v
+----------------------+  +----------------------------+
| MongoDB / Mongoose   |  | Server Filesystem          |
|                      |  |                            |
| Users                |  | Stored uploads             |
| Files                |  | Backup files               |
| File activities      |  | Temporary recovery files   |
| Security events      |  | Rollback files             |
| Refresh sessions     |  |                            |
+----------------------+  +----------------------------+
```

The diagram represents the main logical components. Actual execution paths depend on the specific route, service, and filesystem operation.

---

## 3. Technology and Component Responsibilities

| Component | Technology | Responsibility |
|---|---|---|
| Frontend | React | Presents the dashboard and security information. |
| Backend | Node.js and Express.js | Handles API requests and application orchestration. |
| Database | MongoDB | Persists users, files, activity records, security events, and refresh sessions. |
| Database integration | Mongoose | Defines schemas, validation rules, and model operations. |
| HTTP security middleware | Helmet | Configures HTTP security-related headers. |
| Request logging | Morgan | Logs incoming HTTP requests. |
| Cookie handling | cookie-parser | Parses cookies from incoming requests. |
| Cross-origin configuration | CORS middleware | Configures permitted cross-origin requests. |
| File monitoring | Chokidar-based watcher | Observes filesystem events in the configured storage directory. |
| Integrity verification | Node.js crypto | Calculates SHA-256 hashes of file contents. |
| File storage | Server filesystem | Stores uploaded files and backup files. |

The exact installed dependency versions are defined in the project package manifests.

---

## 4. Frontend Architecture

The frontend source code is located in:

`client/src/`

The current source structure includes:

| File or Component | Responsibility |
|---|---|
| `App.jsx` | Main React application component. |
| `main.jsx` | Frontend entry point. |
| `Sidebar.jsx` | Dashboard sidebar component. |
| `Topbar.jsx` | Dashboard top navigation component. |
| `MetricCard.jsx` | Displays individual dashboard metrics. |
| `SecurityChart.jsx` | Presents security-related information in chart form. |
| `SecurityEventsTable.jsx` | Presents security event records. |
| `BackupHealth.jsx` | Presents backup-related status information. |
| `Badge.jsx` | Reusable status or label component. |
| `App.css` | Application-specific styles. |
| `index.css` | Global styles. |

These components establish the current dashboard structure.

The precise data-fetching behavior, state management, and interaction between components should be documented separately after reviewing the frontend implementation.

### Frontend Responsibilities

The frontend is responsible for:

- Presenting information received from the backend.
- Collecting user input.
- Initiating supported API operations.
- Displaying file integrity and security information.
- Communicating operation results to the user.

The backend remains responsible for enforcing authorization, validating operations, and performing security-sensitive filesystem actions.

---

## 5. Backend Architecture

The backend source code is located in:

`server/src/`

The backend uses a modular structure that separates request handling from business logic and persistence.

### 5.1 Application Entry Point

File:

`server/src/app.js`

The Express application configures the following middleware:

- Helmet.
- Morgan request logging.
- JSON body parsing.
- URL-encoded body parsing.
- Cookie parsing.
- CORS with the configured client origin and credentials.
- API routes mounted under `/api`.
- A not-found handler.
- A centralized error handler.

The main API router is mounted at:

`/api`

For example, a health endpoint defined as `GET /health` in the router is exposed through the application as:

`GET /api/health`

### 5.2 Server Startup

File:

`server/src/server.js`

This file contains the server startup logic.

The exact startup sequence, database connection handling, and initialization of background services should be verified against this file.

The filesystem monitor must be initialized successfully for real-time monitoring to operate. Its presence in the service directory alone does not prove that it starts automatically.

### 5.3 Routes

Directory:

`server/src/routes/`

Routes map HTTP methods and URL paths to the appropriate controllers and middleware.

The current route modules include:

- Authentication routes.
- File routes.
- Security routes.
- Activity analysis routes.
- Health routes.
- A central route index.

### 5.4 Controllers

Directory:

`server/src/controllers/`

Controllers handle HTTP request and response processing.

Examples include:

- `auth.controller.js`
- `file.controller.js`
- `integrity.controller.js`
- `recovery.controller.js`
- `detection.controller.js`
- `securityEvent.controller.js`
- `activityAnalysis.controller.js`
- `health.controller.js`

Controllers delegate the main application operations to services instead of placing all business logic directly inside route handlers.

### 5.5 Services

Directory:

`server/src/services/`

Services contain application operations and coordinate database access and filesystem work.

Important services include:

| Service | Responsibility |
|---|---|
| `auth.service.js` | User authentication-related operations. |
| `refresh.service.js` | Refresh token session operations. |
| `file.service.js` | File management operations. |
| `fileActivity.service.js` | File activity persistence. |
| `fileMonitor.service.js` | Filesystem monitoring and tracked-file verification. |
| `integrity.service.js` | On-demand file integrity verification. |
| `activityAnalysis.service.js` | Analysis of recent file activities. |
| `detection.service.js` | Detection-related service operations. |
| `detectionEngine.service.js` | Evaluation of suspicious activity signals. |
| `securityEvent.service.js` | Security event persistence and related operations. |
| `recovery.service.js` | Backup-based file recovery. |
| `health.service.js` | Health status operations. |

### 5.6 Models

Directory:

`server/src/models/`

Mongoose models define the principal database entities:

- User.
- File.
- FileActivity.
- SecurityEvent.
- RefreshSession.

Their fields, constraints, and relationships are documented in `docs/database/database-schema.md`.

### 5.7 Middleware and Utilities

Middleware is located in:

`server/src/middleware/`

It includes authentication, authorization, owner checks, request validation, upload handling, and error handling.

Shared utilities are located in:

`server/src/utils/`

They include file validation, storage path resolution, refresh token helpers, file extension handling, application errors, response helpers, and risk scoring.

Each middleware must be applied to the appropriate route. The existence of authentication or authorization middleware does not automatically protect every endpoint.

---

## 6. File Upload and Storage Workflow

The file upload workflow is coordinated by the file routes, controller, and service layer.

The high-level flow is:

```text
Client
  |
  | Upload request
  v
Authentication Middleware
  |
  v
Upload Middleware
  |
  v
File Controller
  |
  v
File Service
  |
  +----------------------+
  |                      |
  v                      v
Primary File Storage   Backup Storage
  |                      |
  +-----------+----------+
              |
              v
       File Metadata
          in MongoDB
```

The diagram represents the logical workflow. The exact ordering of physical file writes, backup creation, hashing, and database persistence must be verified in the file service implementation.

### Important Design Considerations

- Uploaded files must be validated by the backend.
- Client-supplied filenames must not be trusted as filesystem paths.
- File storage names should be generated or controlled by the server.
- File ownership must be enforced when accessing stored files.
- Database metadata and physical file operations must be kept consistent.
- Failed uploads should not leave uncontrolled temporary files or inconsistent records.

---

## 7. File Integrity Monitoring

Cloud-Shield uses SHA-256 hashes to compare current file contents with a stored baseline.

The filesystem monitoring service uses a watcher to observe filesystem events in the configured root directory.

The observed events include:

- File additions.
- File changes.
- File deletions.

The watcher ignores the configured backup directory and its descendants.

### 7.1 Monitoring Workflow

```text
Filesystem Event
       |
       v
Watcher Event Handler
       |
       v
Debounced Verification
       |
       v
Find Tracked File Metadata
       |
       v
Read Stored File
       |
       v
Calculate SHA-256 Hash
       |
       v
Compare With Trusted Baseline
       |
       +-----------------------------+
       |              |              |
       v              v              v
     Intact         Modified       Missing
       |              |              |
       v              +------+-------+
                            |
                            v
                  Update Integrity Status
                            |
                            v
                 Persist Security Event
                 When Required
```

### 7.2 Debouncing

The monitor debounces repeated filesystem notifications for the same stored filename.

When another event arrives for a file with a pending timer, the previous timer is cleared and replaced.

This reduces redundant verification when a single file write produces multiple filesystem notifications.

The watcher also uses an `awaitWriteFinish` configuration to reduce the likelihood of checking a file before a write has settled.

These mechanisms reduce noisy checks but do not guarantee that every filesystem event is observed.

### 7.3 Trusted Baseline Comparison

For a tracked file, the monitor:

1. Loads the file's database metadata.
2. Requires an existing trusted baseline hash.
3. Reads the current stored file.
4. Calculates its SHA-256 hash.
5. Compares the calculated hash with the recorded hash.
6. Updates the integrity status when necessary.
7. Persists an integrity violation event for a newly observed modified or missing state.

The monitor uses these integrity states:

| State | Meaning |
|---|---|
| `intact` | Current file contents match the recorded baseline. |
| `modified` | Current file contents differ from the baseline. |
| `unavailable` | The tracked file is missing from storage. |

### 7.4 Duplicate Event Suppression

The monitor keeps an in-memory map of the last successfully reported state for each tracked file.

If the same observed hash or missing state is seen again, the monitor avoids creating another event for that same state.

The marker is cleared when the file returns to the trusted baseline.

Because the marker is held in memory, it does not provide durable deduplication across process restarts. Persistent event constraints provide a separate database-level control.

### 7.5 Monitoring Limitations

- Filesystem watcher events can be missed during downtime or under operating-system limitations.
- An in-memory watcher cannot independently establish a complete history of changes that occurred while the application was stopped.
- Monitoring a storage directory does not automatically monitor every directory on a user's computer.
- The current design compares file contents against stored hashes; it does not prove that every modification was caused by ransomware.
- File integrity detection is not equivalent to automatic ransomware prevention.

A production deployment should evaluate watcher reliability, periodic reconciliation, monitoring health, and the consequences of missed events.

---

## 8. On-Demand Integrity Verification

The integrity service provides a separate path for checking a file when an API request asks for verification.

Its workflow is:

1. Find the file record using both the file ID and authenticated user ID.
2. Resolve the physical file path using the server-controlled stored filename.
3. Read the file contents.
4. Calculate the current SHA-256 hash.
5. Compare the result with the recorded baseline.
6. Update the integrity status.
7. Persist an integrity violation event when the hashes differ.
8. Return the expected hash, current hash, and integrity status.

If the physical file cannot be read, the service marks its integrity status as unavailable and returns an error.

This service complements filesystem monitoring by providing an on-demand check.

The monitor and on-demand integrity service are separate execution paths. Their event deduplication behavior should not be assumed to be identical.

---

## 9. Suspicious Activity Detection

Cloud-Shield analyzes recent file activity to identify patterns that may warrant investigation.

The detection engine uses an activity analysis service to obtain recent activity and derive detection signals.

The default analysis window is 30 seconds. The detection engine accepts a window between 1 and 300 seconds.

### 9.1 Detection Rules

The current detection engine defines the following rules:

| Signal | Trigger Condition | Severity |
|---|---|---|
| `mass_file_modification` | At least three distinct files have modification activities. | Medium |
| `rapid_file_modification` | More than three modifications occur in a window no longer than 30 seconds. | High |
| `multiple_extension_changes` | At least two extension changes occur in a window no longer than 30 seconds. | High |
| `mass_file_rename` | At least three rename activities occur in a window no longer than 30 seconds. | Medium |

The rules evaluate observed activity patterns. They do not independently prove that ransomware is present.

### 9.2 Risk Scores

The detection engine maps severity levels to numeric risk scores:

| Severity | Risk Score |
|---|---:|
| Low | 15 |
| Medium | 45 |
| High | 65 |
| Critical | 90 |

These scores support prioritization and are not proof of a successful attack.

### 9.3 Event Persistence

For each detection signal, the engine:

1. Identifies the activities relevant to the signal.
2. Determines the affected file IDs.
3. Generates a deterministic episode identifier from the signal type and triggering activity IDs.
4. Creates a security event for each affected file.
5. Includes the detection type, risk score, reason, and evidence metadata.

The SecurityEvent model's partial unique indexes provide additional protection against certain duplicate event records.

Detection depends on the available activity records and the configured analysis window. Missed or incomplete activity records can affect detection results.

---

## 10. Backup-Based Recovery

The recovery service restores a tracked file using its stored backup metadata.

Recovery is designed to avoid replacing the original file until the backup has passed integrity verification.

### 10.1 Recovery Workflow

```text
Recovery Request
       |
       v
Verify File Ownership
       |
       v
Load Backup Metadata
       |
       v
Read Backup File
       |
       v
Verify Backup SHA-256
       |
       v
Write Unique Temporary File
       |
       v
Verify Temporary File Hash
       |
       v
Preserve Existing File
Using Rollback File
       |
       v
Install Recovered File
       |
       v
Verify Installed File Hash
       |
       v
Update Database Integrity Status
       |
       v
Record Recovery Activity
```

### 10.2 Recovery Safeguards

The recovery implementation includes the following safeguards:

- It checks file ownership before recovery.
- It requires backup metadata and a backup hash.
- It resolves storage paths through a shared path-resolution utility.
- It verifies the backup hash before restoring it.
- It creates a uniquely named temporary file using exclusive creation.
- It verifies the temporary file against the trusted baseline.
- It preserves an existing file in a rollback location before installing the replacement.
- It verifies the installed file after replacement.
- It updates the database integrity status after the restored file passes verification.
- It attempts to restore the previous filesystem state if recovery fails.
- It records successful or failed recovery activity.

### 10.3 Recovery Limitations

Recovery is not guaranteed to succeed in every situation.

Possible failure conditions include:

- Missing backup files.
- Backup hash mismatches.
- Insufficient filesystem permissions.
- Disk space exhaustion.
- Filesystem errors.
- Database persistence failures.
- Rollback failures.

A rollback failure requires operational investigation and may require manual recovery.

The backup's actual resilience depends on storage permissions, isolation, deployment configuration, and whether an attacker can modify both primary and backup files.

---

## 11. Authentication and Authorization

Cloud-Shield uses authentication middleware and cookie-based access and refresh token handling.

The authentication controller sets access and refresh token cookies after a successful login.

The cookie configuration includes:

- `httpOnly: true`
- `secure` enabled when `NODE_ENV` is `production`
- `sameSite: "strict"`

The access cookie has a configured lifetime of 15 minutes, and the refresh cookie has a configured lifetime of 4 hours.

The refresh flow uses the refresh token cookie to request replacement tokens.

### Authorization Responsibilities

Authentication establishes the identity associated with a request. Authorization determines whether that identity may perform the requested operation.

Sensitive file operations should enforce ownership restrictions at the service or query layer.

For example, the integrity service and recovery service query file metadata using both the file ID and user ID.

This prevents those service operations from relying on the file ID alone as proof of permission.

### Security Considerations

- Cookie-based authentication requires appropriate protection against cross-site request forgery in the application's deployment context.
- CORS configuration should permit only trusted frontend origins.
- Production deployments should use HTTPS.
- Authentication and authorization middleware must be applied consistently to protected routes.
- Secrets must be stored in environment configuration and must not be committed to version control.
- Refresh token rotation, revocation, and session validation should be tested independently.

---

## 12. Database Architecture

MongoDB stores the application's persistent metadata.

The principal models are:

| Model | Purpose |
|---|---|
| User | Account details, roles, account status, and storage limits. |
| File | Stored file metadata, integrity hashes, backup metadata, and status. |
| FileActivity | Recorded file operations and associated names or extensions. |
| SecurityEvent | Integrity violations and suspicious activity events. |
| RefreshSession | Refresh token session metadata and revocation state. |

Mongoose defines schema-level validation and configured indexes.

MongoDB references between these documents are application-managed relationships rather than automatically enforced SQL-style foreign keys.

Detailed field definitions and constraints are documented in:

`docs/database/database-schema.md`

---

## 13. Error Handling and Logging

The Express application includes request logging, a not-found handler, and centralized error handling.

The service layer also logs selected operational failures, including filesystem monitoring errors and recovery cleanup or rollback failures.

These mechanisms help operators investigate errors and unexpected states.

Production logging should be configured to avoid exposing secrets, authentication tokens, sensitive file contents, or unnecessary personal information.

Security-relevant failures should be observable without revealing sensitive implementation details in client-facing error responses.

---

## 14. Security Boundaries

Cloud-Shield's security depends on more than detecting changes in file hashes.

Important boundaries include:

### API Boundary

- Validate incoming requests.
- Authenticate protected operations.
- Enforce authorization and file ownership.
- Avoid exposing internal error details.

### Database Boundary

- Restrict database credentials and network access.
- Validate persisted data.
- Protect security event records from unauthorized modification.
- Back up database metadata and test restoration.

### Filesystem Boundary

- Resolve paths using server-controlled storage names.
- Prevent path traversal.
- Apply appropriate filesystem permissions.
- Separate backup storage from untrusted upload handling where practical.
- Verify file contents before recovery.

### Monitoring Boundary

- Track monitoring initialization and runtime health.
- Handle missed events and watcher errors.
- Consider periodic integrity reconciliation.
- Avoid treating suspicious activity signals as definitive proof of ransomware.

### Recovery Boundary

- Verify backup integrity before restoration.
- Preserve the previous file when feasible.
- Verify the installed result.
- Record recovery outcomes.
- Maintain independently protected backups where possible.

---

## 15. Reliability and Performance Considerations

### Filesystem Monitoring

Debouncing reduces repeated checks for noisy events, but reading entire files into memory can consume significant memory and I/O for large uploads.

Production deployments should establish file-size limits and evaluate resource usage under realistic workloads.

### Database Queries

Indexes support selected lookups and event deduplication. Additional indexes should be introduced based on measured query patterns and execution plans.

### Detection

Detection cost depends on the number of activity records retrieved and the number of signals generated.

The analysis window and query limits should be evaluated against expected activity volume.

### Recovery

Recovery reads the backup, writes a temporary file, and reads the restored file for verification.

This improves confidence in the restored content but increases filesystem I/O.

### Process Restarts

In-memory monitoring state is lost when the process restarts.

A production design should account for monitoring reinitialization, missed filesystem events, and reconciliation of stored metadata with actual files.

---

## 16. Production Readiness Considerations

Before production deployment, evaluate:

1. Reliable startup and shutdown of the filesystem monitor.
2. Periodic integrity reconciliation after downtime.
3. Strict upload size and file-type validation.
4. User-scoped authorization for every sensitive endpoint.
5. Database indexes and query performance under realistic data volumes.
6. Protected and independently recoverable backups.
7. Refresh token rotation and revocation behavior.
8. CSRF protection appropriate for cookie-based authentication.
9. Monitoring health, structured logs, and operational alerting.
10. Recovery testing, including disk failures and rollback failures.
11. Resource limits for large files and high activity volumes.
12. Tests for missed events, duplicate events, and concurrent operations.

These are operational and security review areas, not claims that every item is currently implemented.

---

## 17. Conclusion

Cloud-Shield uses a modular architecture that separates the frontend, API handling, business logic, persistence, and filesystem operations.

Its principal security workflows combine SHA-256 integrity verification, filesystem event monitoring, recent-activity analysis, security event persistence, and backup-based recovery.

The architecture provides a foundation for file integrity monitoring and suspicious activity analysis. Its effectiveness in production depends on monitoring reliability, authorization, backup isolation, recovery validation, operational observability, and testing against realistic failure scenarios.