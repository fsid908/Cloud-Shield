import { Router } from "express";
import authController from "../controllers/auth.controller.js";
import validate from "../middleware/validate.middleware.js";
import { registerSchema, LoginSchema, } from "../validators/auth.validators.js";
import authenticate from "../middleware/auth.middleware.js";
import refreshController from "../controllers/refresh.controller.js";
// import authenticate from "../middleware/authorize.middleware.js"; //see later
import authorize from "../middleware/authorize.middleware.js";
import {
    loginLimiter,
    registerLimiter,
    refreshLimiter,
    logoutLimiter,
} from "../middleware/rateLimit.middleware.js";

//router 
const router = Router();

// register route
router.post("/register", registerLimiter, validate(registerSchema), authController.register);

//login route 
router.post( "/login", loginLimiter, validate(LoginSchema), authController.login);

// login me
router.get("/me", authenticate, authController.me);

// update user profile
router.put("/update-profile", authenticate, authController.updateProfile);

// admin only test route
// router.get("/admin-test", authenticate,authorize("admin"), 
// (req, res) => {
//     return res.status(200).json({
//         success: true,
//         message: "Admin authorization successful.",
//     });
// });

//logout
router.post("/logout", logoutLimiter, authController.logout)

// refresh access token
router.post("/refresh", refreshLimiter, refreshController.refresh)

export default router; 