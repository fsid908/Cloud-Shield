import authService from "../services/auth.service.js";
import refreshService from "../services/refresh.service.js";
import { sendSuccess } from "../utils/response.js";

// register user 
const register = async (req, res, next) => {
    try {
        const user = await authService.registerUser(req.body);
        return sendSuccess(res, 201, "User registerd successfully", user);
    } catch (error) {
        next(error);
    }
};

//login user 
const login = async (req, res, next) => {
    try {
        const { email, password } = req.body;
        // collect request information refresh-session tracking
        const sessionInfo = {
            userAgent: req.get("user-agent"),
            ipAddress: req.ip,
        };

        // authenticate user and create access and refresh toekns
        const { user, token, refreshToken } = await authService.loginUser( email, password, sessionInfo );

        // store access token in  HttpOnly cookie
        res.cookie("accessToken", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 15 *60 * 1000,   // session out time is 15 minutes 
        });

        // store refresh token in HttpOnly cookie
        res.cookie("refreshToken", refreshToken,{
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 4 * 60 * 60 * 1000,
        });
        
        //return informatuion without authentication token
        return sendSuccess(res, 200, " Loginsuccessfull",{ user, });
      } catch (error) {
        next(error)
    }
};

const me = async (req, res, next) => {
    try {
        return sendSuccess(res, 200,"Authenticated user.",req.user);
    } catch (error) {
        next(error);
    }   
};
const updateProfile = async (req, res, next) => {
    try {
        const updatedUser = await authService.updateUserProfile(
            req.user._id,
            req.body
        );

        return sendSuccess(
            res,
            200,
            "Profile updated successfully.",
            updatedUser
        );
    } catch (error) {
        next(error);
    }
};
//  for logout
const logout = async (req, res, next) => {
    try {
        // get refresh token from HttpOnly cookie
        const refreshToken = req.cookies.refreshToken;

        // revoke refresh session on the server
        await refreshService.revokeRefreshToken(refreshToken);

        // clear access token cookie
        res.clearCookie("accessToken", {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
        });

        // clear refresh token cookie
        res.clearCookie("refreshToken", {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
        });

        // return successful logout response
        return sendSuccess(
            res,
            200,
            "Logout successful.",
            null
        );
    } catch (error) {
        next(error);
    }
};

export default {
    register,
    login,
    me,
    logout,
    updateProfile,
};
