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

const router = express.Router();

router.post("/register", validateRequest(registerSchema), register);

router.post("/login", validateRequest(loginSchema), login);

router.post("/refreshToken", refreshAccessToken);

router.post("/logout", logout);

router.post("/logoutAll", logoutAll);

export default router;
