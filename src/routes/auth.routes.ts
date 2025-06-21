import express from "express";
import {
  login,
  logout,
  logoutAll,
  refreshAccessToken,
  register,
} from "../controllers/auth.controller";
import { validateRequest } from "../middlewares/validateRequest";
import { loginSchema, registerSchema } from "../validators/auth.validator";
import { verifyToken } from "../middlewares/auth.middleware";
import { verifyOtp } from "../controllers/verify.otp";
import { resendOtp } from "../controllers/resendotp";
import { forgotPassword, resetPassword } from "../controllers/forgetPassword";

const router = express.Router();

router.post("/register", validateRequest(registerSchema), register);

router.post("/login", validateRequest(loginSchema), login);

router.get("/refresh-token", verifyToken, refreshAccessToken);

router.post("/logout", verifyToken, logout);

router.post("/logout-all", verifyToken, logoutAll);

router.post("/verify-otp", verifyOtp);

router.post("/resend-otp", resendOtp);

router.post("/forgotPassword", forgotPassword);
router.post("/resetPassword", resetPassword);

export default router;
