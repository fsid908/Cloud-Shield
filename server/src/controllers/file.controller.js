import fileService from "../services/file.service.js";
import AppError from "../utils/AppError.js";
import { sendSuccess } from "../utils/response.js";

// create file metadata
const createFile = async (req, res, next) => {
  try {
    // Multer places the uploaded file in req.file
    if (!req.file) {
      throw new AppError("File is required.", 400);
    }

    // Authentication middleware provides the authenticated user
    const userId = req.user._id;

    // Pass the actual uploaded file to the service
    const file = await fileService.createFile(userId, req.file);

    const message =
      file.status === "quarantined"
        ? "Malware detected! File has been quarantined."
        : "File uploaded successfully.";

    return sendSuccess(res, 201, message, file);
  } catch (error) {
    next(error);
  }
};

//get file owned by authenticated user
const getFile = async (req, res, next) => {
  try {
    // get authenticated user
    const userId = req.user._id;

    // get file ID  from URL parameter
    const { fileId } = req.params;

    // service enforces ownership
    const file = await fileService.getUserFile(fileId, userId);

    // return file metadata
    return sendSuccess(res, 200, " file retrived successfully.", file);
  } catch (error) {
    next(error);
  }
};

const getUserFiles = async (req, res, next) => {
  try {
    const userId = req.user._id;
    const files = await fileService.getUserFiles(userId);

    return sendSuccess(res, 200, "Files retrieved successfully.", files);
  } catch (error) {
    next(error);
  }
};

export default {
  createFile,
  getFile,
  getUserFiles,
};
