import { Router } from "express";
import authenticate from "../middleware/auth.middleware.js";
import detectionController from "../controllers/detection.controller.js";
import securityEventController from "../controllers/securityEvent.controller.js";

const router = Router();
router.get("/activity", authenticate, detectionController.getRecentActivity);

// Analyze recent file activity for suspicious signals.
router.get(
  "/detection",
  authenticate,
  detectionController.detectSuspiciousActivity,
);

// Retrieve paginated security events.
router.get("/events", authenticate, securityEventController.getSecurityEvents);

export default router;
