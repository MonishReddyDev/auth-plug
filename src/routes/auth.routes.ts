import express from "express";
import {
  loginUser,
  logoutAllHandler,
  refreshTokenHandler,
  registerUser,
} from "../controllers/auth.controller";
import { verifyOtpController } from "../controllers/email.controller";
import { validateRequest } from "../middlewares/validateRequest";
import { loginSchema, registerSchema } from "../validators/auth.validator";
import { verifyToken } from "../middlewares/auth.middleware";
import { resendOtpController } from "../controllers/email.controller";
import {
  forgotPasswordController,
  resetPasswordController,
} from "../controllers/password.controller";

const router = express.Router();

router.post("/register", validateRequest(registerSchema), registerUser);
router.post("/login", validateRequest(loginSchema), loginUser);
router.get("/refresh-token", refreshTokenHandler);
router.post("/logout", verifyToken, logoutAllHandler);
router.post("/logout-all", verifyToken, logoutAllHandler);

router.post("/verify-otp", verifyOtpController);
router.post("/resend-otp", resendOtpController);

router.post("/forgot-password", forgotPasswordController);
router.post("/reset-password", resetPasswordController);


export default router;
