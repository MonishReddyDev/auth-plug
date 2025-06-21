import { Request, Response } from "express";
import {
  handleForgotPassword,
  handleResetPassword,
} from "../services/password.service";

export const forgotPasswordController = async (req: Request, res: Response) => {
  const { email } = req.body;
  const result = await handleForgotPassword(email);

  res.status(result.status).json({ message: result.message });
};

export const resetPasswordController = async (req: Request, res: Response) => {
  const { email, otp, newPassword } = req.body;
  const result = await handleResetPassword(email, otp, newPassword);

  res.status(result.status).json({ message: result.message });
};
