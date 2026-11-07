import { Router } from "express";
import fileController from "../controllers/file.controller.js";
import authenticate from "../middleware/auth.middleware.js"; 
import upload from "../middleware/upload.middleware.js";
import integrityController from "../controllers/integrity.controller.js";
import recoveryController from "../controllers/recovery.controller.js";

const router = Router();

// create/ upload file metadata for authenticated user 
router.post("/", authenticate, upload.single("file"),
fileController.createFile);
router.get("/", authenticate, fileController.getUserFiles);
// get file owned by authenticated user 
router.get("/:fileId", authenticate,fileController.getFile);

// file integrity check  
router.get ("/:fileId/integrity", authenticate, integrityController.checkIntegrity);

// recover File fro trusted bsckup
router.post("/:fileId/recover", authenticate, recoveryController.recoverFile);

export default router;