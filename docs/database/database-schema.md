# Cloud-Shield Database Schema

## 1. Overview

Cloud-Shield uses MongoDB as its primary database and Mongoose to define schemas, validate document fields, and interact with stored data.

The database supports the following core functionality:

- User account management.
- Uploaded file metadata and integrity verification.
- File activity tracking.
- Security event recording and suspicious activity analysis.
- Refresh token session management.

The current data model contains five primary collections:

| Collection | Purpose |
|---|---|
| `users` | Stores user account information and storage limits. |
| `files` | Stores uploaded file metadata, integrity hashes, and backup information. |
| `fileactivities` | Records file-related activities. |
| `securityevents` | Stores integrity violations and security detection events. |
| `refreshsessions` | Stores refresh token session metadata. |

> **Note:** Collection names shown here are the expected Mongoose pluralized names. Verify the actual collection names in MongoDB if the application configures custom collection names.

---

## 2. Entity Relationship Overview

The primary relationships between the models are:

- One user can own multiple files.
- One user can have multiple file activity records.
- One file can have multiple file activity records.
- One user can have multiple security events.
- One file can have multiple security events.
- One user can have multiple refresh sessions.

These relationships are represented through MongoDB ObjectId references.

### Relationship Summary

| Parent Model | Child Model | Relationship | Reference Field |
|---|---|---|---|
| User | File | One-to-many | `File.userId` |
| User | FileActivity | One-to-many | `FileActivity.userId` |
| File | FileActivity | One-to-many | `FileActivity.fileId` |
| User | SecurityEvent | One-to-many | `SecurityEvent.userId` |
| File | SecurityEvent | One-to-many | `SecurityEvent.fileId` |
| User | RefreshSession | One-to-many | `RefreshSession.userId` |

These are logical references. MongoDB does not automatically enforce relational foreign-key constraints like a traditional SQL database.

---

## 3. User Model

**Model file:** `server/src/models/user.model.js`

The User model stores account details, account status, and storage usage information.

### Fields

| Field | Type | Required | Default / Constraints | Description |
|---|---|---|---|---|
| `fullName` | String | Yes | Trimmed; minimum 3 and maximum 100 characters | User's full name. |
| `email` | String | Yes | Unique, lowercase, trimmed | User's email address. |
| `password` | String | Yes | No schema-level default | Password-related field. |
| `role` | String | Yes | Enum: `user`, `admin`; default: `user` | User's application role. |
| `isVerified` | Boolean | No | Default: `false` | Indicates whether the account is verified. |
| `accountStatus` | String | No | Enum: `active`, `suspended`, `blocked`; default: `active` | Current account status. |
| `storageUsed` | Number | No | Default: `0` | Recorded storage usage. |
| `storageLimit` | Number | No | Default: `5 * 1024 * 1024 * 1024` bytes | Configured storage limit. |
| `lastLogin` | Date | No | Default: `null` | Last login timestamp, when available. |
| `createdAt` | Date | Automatically managed | Mongoose timestamps | Document creation time. |
| `updatedAt` | Date | Automatically managed | Mongoose timestamps | Last document update time. |

### Important Details

- The default storage limit is 5 GiB, calculated as `5 × 1024³` bytes.
- Email uniqueness is configured in the schema.
- `role` and `accountStatus` use enumerated values to restrict accepted values.
- Mongoose timestamps automatically maintain `createdAt` and `updatedAt`.

### Security Considerations

- Password hashing must be verified in the authentication service. The schema alone does not establish whether passwords are hashed before storage.
- Authentication and authorization logic must enforce the intended permissions associated with each role.
- Storage limits should be checked by the backend when accepting uploads. A schema default does not enforce an upload quota by itself.
- Account status should be checked in the relevant authentication and authorization flows.

---

## 4. File Model

**Model file:** `server/src/models/file.model.js`

The File model stores metadata for uploaded files, their integrity hashes, backup information, and current security status.

### Fields

| Field | Type | Required | Default / Constraints | Description |
|---|---|---|---|---|
| `userId` | ObjectId | Yes | References `User`; indexed | Owner of the file record. |
| `originalName` | String | Yes | Trimmed; maximum 255 characters | Original uploaded filename. |
| `storedName` | String | Yes | Unique | Name used for the stored file. |
| `storagePath` | String | Yes | No schema-level default | Storage location of the primary file. |
| `mimeType` | String | Yes | No schema-level default | Recorded MIME type. |
| `size` | Number | Yes | Minimum: `0` | Recorded file size. |
| `hash` | String | Yes | Indexed | Integrity hash of the primary file. |
| `backupStoredName` | String | Yes | Unique | Name used for the backup file. |
| `backupStoragePath` | String | Yes | No schema-level default | Storage location of the backup file. |
| `backupHash` | String | Yes | Indexed | Integrity hash of the backup file. |
| `status` | String | Yes | Enum: `pending`, `safe`, `suspicious`, `infected`, `quarantined`; default: `pending`; indexed | Recorded security status. |
| `integrityStatus` | String | Yes | Enum: `intact`, `modified`, `unavailable`; default: `intact`; indexed | Recorded integrity status. |
| `createdAt` | Date | Automatically managed | Mongoose timestamps | Document creation time. |
| `updatedAt` | Date | Automatically managed | Mongoose timestamps | Last document update time. |

### Important Details

- `userId` associates each file record with its owner.
- `hash` supports integrity verification by recording a file hash.
- `backupHash` records the expected hash associated with the backup.
- The status fields represent the file's recorded security and integrity state.
- Unique constraints are configured for `storedName` and `backupStoredName`.

### Security Considerations

- File ownership must be checked on every operation that accesses, checks, or recovers a file.
- A client-provided filename must not be trusted as a filesystem path.
- File size and actual content should be validated during upload.
- A MIME type supplied by the client should not be treated as proof of file content.
- File hashes should be calculated by trusted backend code rather than accepted from clients.
- Backup integrity should be verified before recovery.
- Database metadata and filesystem operations must remain consistent when a file is replaced, deleted, or recovered.

> **Important:** The presence of a file record and backup metadata does not, by itself, guarantee that the backup is isolated from ransomware or that recovery will always succeed.

---

## 5. FileActivity Model

**Model file:** `server/src/models/fileActivity.model.js`

The FileActivity model records activities associated with a user's file.

### Fields

| Field | Type | Required | Default / Constraints | Description |
|---|---|---|---|---|
| `userId` | ObjectId | Yes | References `User`; indexed | User associated with the activity. |
| `fileId` | ObjectId | Yes | References `File`; indexed | File associated with the activity. |
| `activityType` | String | Yes | Enum: `created`, `modified`, `renamed`, `deleted`, `recovered`, `recovery_failed`; indexed | Type of recorded activity. |
| `previousName` | String | No | Default: `null`; trimmed | Previous filename, when available. |
| `currentName` | String | No | Default: `null`; trimmed | Current filename, when available. |
| `previousExtension` | String | No | Default: `null`; trimmed | Previous file extension, when available. |
| `currentExtension` | String | No | Default: `null`; trimmed | Current file extension, when available. |
| `createdAt` | Date | Automatically managed | Mongoose timestamps | Time the activity record was created. |
| `updatedAt` | Date | Automatically managed | Mongoose timestamps | Time the activity record was last updated. |

### Supported Activity Types

| Activity Type | Meaning |
|---|---|
| `created` | A file creation activity was recorded. |
| `modified` | A file modification activity was recorded. |
| `renamed` | A file rename activity was recorded. |
| `deleted` | A file deletion activity was recorded. |
| `recovered` | A file recovery activity was recorded. |
| `recovery_failed` | A recovery failure was recorded. |

### Important Details

- The model links an activity to both a user and a file.
- Previous and current filename or extension fields support tracking relevant changes.
- The `createdAt` timestamp can be used to order activities chronologically.

### Security Considerations

- Activity records should be created by trusted backend services.
- User-facing activity queries must be scoped to the authenticated user.
- Activity history should not be treated as tamper-proof merely because it is stored in MongoDB.
- Retention policies should account for database growth as activity records accumulate.

---

## 6. SecurityEvent Model

**Model file:** `server/src/models/securityEvent.model.js`

The SecurityEvent model stores security-related events, including file integrity violations and suspicious activity detections.

### Fields

| Field | Type | Required | Default / Constraints | Description |
|---|---|---|---|---|
| `userId` | ObjectId | Yes | References `User`; indexed | User associated with the event. |
| `fileId` | ObjectId | Yes | References `File`; indexed | File associated with the event. |
| `eventType` | String | Yes | Enum: `integrity_violation`, `suspicious_activity`, `ransomware_detected`; indexed | Category of the security event. |
| `previousHash` | String | No | Default: `null` | Previous recorded hash, when available. |
| `currentHash` | String | No | Default: `null` | Current observed hash, when available. |
| `detectionType` | String | No | Default: `null`; trimmed; maximum 100 characters | Detection classification. |
| `episodeId` | String | No | Default: `null`; trimmed; maximum 128 characters | Identifier associated with a detection episode. |
| `riskScore` | Number | No | Range: 0–100; default: `0` | Recorded risk score. |
| `reason` | String | Yes | Trimmed; maximum 500 characters | Explanation recorded for the event. |
| `previousExtension` | String | No | Default: `null`; trimmed | Previous file extension, when available. |
| `currentExtension` | String | No | Default: `null`; trimmed | Current file extension, when available. |
| `metadata` | Mixed | No | Default: `{}` | Additional event metadata. |
| `createdAt` | Date | Automatically managed | Mongoose timestamps | Event creation time. |
| `updatedAt` | Date | Automatically managed | Mongoose timestamps | Last document update time. |

### Supported Event Types

| Event Type | Meaning |
|---|---|
| `integrity_violation` | A file integrity violation was recorded. |
| `suspicious_activity` | Activity classified as suspicious was recorded. |
| `ransomware_detected` | An event classified as ransomware detection was recorded. |

These values describe the event categories supported by the schema. They do not, by themselves, establish the accuracy of the detection algorithm.

### Indexes and Deduplication

The schema defines two partial unique indexes.

#### 1. Integrity Transition Index

Index name:

`unique_security_event_transition_integrity`

Indexed fields:

- `userId`
- `fileId`
- `eventType`
- `previousHash`
- `currentHash`

The index is unique and applies to documents whose `eventType` is `integrity_violation`.

Its purpose is to prevent duplicate records for the same indexed integrity transition.

#### 2. Detection Episode Index

Index name:

`unique_security_event_episode`

Indexed fields:

- `userId`
- `fileId`
- `eventType`
- `detectionType`
- `episodeId`

The index is unique and applies when `episodeId` is a string.

Its purpose is to prevent duplicate records for the same indexed detection episode.

> MongoDB's handling of unique indexes and partial filter expressions affects which documents can coexist. Test these constraints against the actual database, including documents with missing or `null` values.

### Security Considerations

- Security events should be generated by trusted backend components.
- User-facing queries must enforce ownership restrictions.
- The `metadata` field uses the flexible Mixed type. Validate the structure and size of data written to it.
- Do not store credentials, access tokens, refresh tokens, or other secrets in event metadata.
- A risk score is an application-generated value, not proof that a file is malicious.
- Production deployments should consider event retention, restricted database permissions, and protection against unauthorized modification.

---

## 7. RefreshSession Model

**Model file:** `server/src/models/refreshSession.model.js`

The RefreshSession model stores metadata associated with refresh token sessions.

### Fields

| Field | Type | Required / Default / Constraints | Description |
|---|---|---|---|
| `userId` | ObjectId | Configured as required; index option present | References the user associated with the session. |
| `familyId` | ObjectId | Required; indexed; UUID type | Groups related refresh sessions into a family. |
| `tokenHash` | String | Required; unique | Stores the refresh token hash. |
| `lastUsedAt` | Date | Required | Time the session was last used. |
| `expiresAt` | Date | Required; indexed | Session expiration time. |
| `revokedAt` | Date | Default: `null` | Time the session was revoked, when applicable. |
| `userAgent` | String | Default: `null` | Recorded client user-agent value. |
| `ipAddress` | String | Default: `null` | Recorded IP address. |
| `createdAt` | Date | Automatically managed | Document creation time. |
| `updatedAt` | Date | Automatically managed | Last document update time. |

### Important Details

- `tokenHash` is configured as unique to prevent duplicate values in that field.
- `expiresAt` records the session's expiration time.
- `revokedAt` records revocation when a session is revoked.
- `familyId` associates related sessions with a shared identifier.

An indexed `expiresAt` field does not automatically delete expired sessions unless a suitable TTL index or explicit cleanup mechanism is configured.

### Security Considerations

- Refresh tokens should be high-entropy secrets, and the database should store only an appropriately generated token hash.
- Refresh token validation, rotation, and revocation must be implemented by the authentication services.
- Expired or revoked sessions must not be accepted as valid sessions.
- Session metadata such as IP address and user-agent should be handled according to the application's privacy and retention requirements.
- Database access should be restricted because session records are security-sensitive.

### Implementation Review Note

The current model source expresses the `required` and `index` options for `userId` as strings rather than Boolean values.

Review these schema options and verify the resulting Mongoose schema behavior. Do not assume that the intended constraints are enforced until they have been tested.

---

## 8. Indexing Strategy

Indexes can improve query performance, but they also consume storage and add overhead to inserts and updates.

The current models configure the following important indexes and constraints:

| Model | Field(s) | Configuration | Purpose |
|---|---|---|---|
| User | `email` | Unique | Prevent duplicate email values. |
| File | `userId` | Index | Support queries associated with a user. |
| File | `storedName` | Unique | Prevent duplicate stored-name values. |
| File | `backupStoredName` | Unique | Prevent duplicate backup-name values. |
| File | `hash` | Index | Support queries using the recorded file hash. |
| File | `backupHash` | Index | Support queries using the backup hash. |
| File | `status` | Index | Support queries filtering by file status. |
| File | `integrityStatus` | Index | Support queries filtering by integrity status. |
| FileActivity | `userId` | Index | Support user-scoped activity queries. |
| FileActivity | `fileId` | Index | Support file-scoped activity queries. |
| FileActivity | `activityType` | Index | Support activity-type filtering. |
| SecurityEvent | `userId` | Index | Support user-scoped event queries. |
| SecurityEvent | `fileId` | Index | Support file-scoped event queries. |
| SecurityEvent | `eventType` | Index | Support event-type filtering. |
| SecurityEvent | Multiple fields | Two partial unique indexes | Deduplicate specific integrity transitions and detection episodes. |
| RefreshSession | `tokenHash` | Unique | Prevent duplicate token hashes. |
| RefreshSession | `expiresAt` | Index | Support expiration-related queries. |

This table summarizes explicitly configured indexes. Mongoose may also create indexes for schema options such as `unique: true`.

### Indexing Recommendations

Before adding additional indexes:

1. Inspect actual database query patterns.
2. Review query execution plans using MongoDB's `explain()` functionality.
3. Measure query latency with realistic data volumes.
4. Evaluate the write overhead and storage cost of additional indexes.
5. Prefer compound indexes that match real filtering and sorting patterns.

Do not add indexes simply because a field appears important. Indexes are useful when they match actual query patterns.

---

## 9. Data Integrity and Validation

Cloud-Shield uses Mongoose schema validation to define constraints on stored documents.

Current schema-level controls include:

- Required fields.
- String trimming.
- Minimum and maximum values.
- Enumerated string values.
- Default values.
- Unique constraints.
- Field indexes.
- Mongoose timestamps.
- Partial unique indexes for selected security events.

These controls help maintain data consistency, but they do not replace service-level validation or authorization.

### Validation Responsibilities

| Layer | Responsibility |
|---|---|
| API validation | Validate incoming request data and reject invalid input. |
| Service layer | Enforce business rules and coordinate operations. |
| Mongoose schema | Validate document fields and configured constraints. |
| MongoDB indexes | Enforce supported uniqueness and indexing rules. |
| Filesystem layer | Validate file operations and handle storage errors safely. |

MongoDB references between documents are not automatically enforced as SQL-style foreign keys. Application logic must handle missing or deleted referenced documents.

---

## 10. Backup and Recovery Data

The File model stores the following backup-related fields:

- `backupStoredName`
- `backupStoragePath`
- `backupHash`

These fields support the application's backup and recovery workflow.

A recovery operation should verify that the backup is available and that its contents match the expected trusted hash before replacing the primary file.

### Operational Considerations

- A database backup is different from a file-content backup.
- Backing up MongoDB alone does not preserve the contents of files stored on disk.
- Backing up files alone does not preserve the associated metadata and security events.
- Recovery procedures should account for both database records and filesystem contents.
- Backup storage should be protected against unauthorized modification and deletion.
- Restore procedures should be tested periodically.

The actual isolation and resilience of backup storage depend on the storage implementation and deployment configuration.

---

## 11. Known Review Items

The following items require verification or further engineering work:

1. **Password handling:** Verify that passwords are securely hashed before being stored.
2. **RefreshSession schema options:** Review the string-valued `required` and `index` options on `userId`.
3. **Session cleanup:** Verify whether expired refresh sessions are deleted by a TTL index, scheduled cleanup, or another mechanism.
4. **Index deployment:** Verify that expected indexes exist in the target MongoDB database.
5. **File ownership:** Verify that every file and security-event operation enforces user ownership.
6. **Storage quotas:** Verify that uploads cannot exceed the configured storage limit through concurrent or repeated requests.
7. **Backup integrity:** Verify that recovery checks the backup against a trusted expected hash.
8. **Event retention:** Define a retention strategy for file activity and security events.
9. **Database recovery:** Document and test database backup and restoration procedures.

These are review items, not claims that the implementation is necessarily incorrect.

---

## 12. Conclusion

The Cloud-Shield database schema separates account data, file metadata, file activity, security events, and refresh session records into dedicated models.

This structure supports separation of concerns and allows each model to define its own validation rules, relationships, and indexes.

Schema definitions are only one part of application security. Production readiness also depends on service-layer authorization, secure authentication, filesystem protections, index verification, reliable backup procedures, and tests against the actual MongoDB deployment.