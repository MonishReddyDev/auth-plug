import { Request, Response } from "express";
import { resendOtpService, verifyOtpService } from "../services/email.service";

export const resendOtpController = async (req: Request, res: Response) => {
  const { email } = req.body;
  const result = await resendOtpService(email);

  res.status(result.status).json({ message: result.message });
};

export const verifyOtpController = async (req: Request, res: Response) => {
  const { email, otp } = req.body;
  const result = await verifyOtpService(email, otp);

  res.status(result.status).json({ message: result.message });
};
