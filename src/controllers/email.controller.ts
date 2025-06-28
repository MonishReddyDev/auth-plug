import { Request, Response } from "express";
import { success, error } from "../utils/response.util";
import { logError } from "../utils/logger.util";
import { resendOtpService, verifyOtpService } from "../services/email.service";

// Resend OTP Controller
export const resendOtpController = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    const result = await resendOtpService(email);

    if (result.status !== 200) {
      error(res, result.message, result.status);
      return;
    }
    success(res, result.message, {}, 200);
    return;
  } catch (err) {
    logError(err, req);
    error(res, "Failed to resend OTP", 500);
    return;
  }
};

// Verify OTP Controller
export const verifyOtpController = async (req: Request, res: Response) => {
  try {
    const { email, otp } = req.body;
    const result = await verifyOtpService(email, otp);

    if (result.status !== 200) {
      error(res, result.message, result.status);
      return;
    }
    success(res, result.message, {}, 200);
    return;
  } catch (err) {
    logError(err, req);
    error(res, "Failed to verify OTP", 500);
    return;
  }
};
