# Changelog

All notable changes to Cloud-Shield are documented in this file.

This changelog follows the principles of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and uses Semantic Versioning where applicable.

The project is under active development. The changelog records implemented features and documented changes, not planned features that have not yet been completed.

## [Unreleased]

### Documentation
- Documented the API endpoints and their authentication requirements.
- Documented the MongoDB schemas, field constraints, indexes, and model relationships.
- Expanded the system architecture documentation to describe the frontend, backend, database, filesystem monitoring, detection, and recovery workflows.

### Maintenance
- Identified areas requiring further verification, including filesystem monitoring reliability, backup protection, and production deployment readiness.

## [0.1.0] - 2026-10-24

### Added
- Implemented paginated security event history API.
- Added support for retrieving security events through the backend API.
- Added pagination parameters for retrieving event history.

### Security
- Applied user-scoped access to security event retrieval.
- Added support for structured security event history.

---

## Project Capabilities

The following capabilities are present in the project codebase. Their completeness and production readiness should be evaluated independently.

### Authentication and Access Control
- User registration and login endpoints.
- Access and refresh token cookie handling.
- Authentication and authorization middleware.
- User-scoped file access checks.

### File Management
- File upload and storage functionality.
- File metadata persistence using MongoDB and Mongoose.
- SHA-256-based file integrity verification.
- Backup metadata associated with stored files.

### Filesystem Monitoring
- Filesystem monitoring using a watcher.
- Debounced verification of tracked files.
- Detection of modified or missing stored files.
- Integrity status updates and security event persistence.

### Security Analysis
- File activity tracking.
- Recent activity analysis.
- Rule-based suspicious activity detection.
- Risk scoring for detection signals.
- Security event history and pagination.

### Recovery
- Backup integrity verification before restoration.
- Temporary-file-based recovery workflow.
- Verification of restored file contents.
- Rollback handling when recovery fails.
- Recovery activity logging.

---

## Changelog Maintenance Guidelines

When updating this file:

- Add new changes under `[Unreleased]` during active development.
- Use `Added` for new features.
- Use `Changed` for changes to existing behavior.
- Use `Fixed` for bug fixes.
- Use `Security` for security-related changes.
- Use `Removed` for removed functionality.
- Move completed release changes into a versioned section when a release is actually created.
- Do not record planned or unverified functionality as completed.
- Keep entries concise and focused on meaningful changes.

[Unreleased]: https://github.com/Farhan8271git/Cloud-Shield/compare/v0.1.0...HEAD