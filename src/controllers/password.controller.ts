import { Request, Response } from "express";
import {
  handleForgotPassword,
  handleResetPassword,
} from "../services/password.service";
import { success, error } from "../utils/response.util";
import { logError } from "../utils/logger.util";

export const forgotPasswordController = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    const result = await handleForgotPassword(email);

    if (result.status !== 200) {
      error(res, result.message, result.status);
      return;
    }
    success(res, result.message, {}, 200);
    return;
  } catch (err) {
    logError(err, req);
    error(res, "Failed to process password reset request", 500);
    return;
  }
};

export const resetPasswordController = async (req: Request, res: Response) => {
  try {
    const { email, otp, newPassword } = req.body;
    const result = await handleResetPassword(email, otp, newPassword);

    if (result.status !== 200) {
      error(res, result.message, result.status);
      return;
    }
    success(res, result.message, {}, 200);
    return;
  } catch (err) {
    logError(err, req);
    error(res, "Failed to reset password", 500);
    return;
  }
};
