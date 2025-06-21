import prisma from "../config/prisma";
import { Request, Response } from "express";
import { generateOtp } from "../services/otp.service";
import { hashToken, verifyHashedToken } from "../utils/hash.util";
import { sendOtpEmail } from "../services/sendEmail.service";
import bcrypt from "bcryptjs";

export const forgotPassword = async (req: Request, res: Response) => {
  const { email } = req.body;

  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    res.status(200).json({
      message: "If the email is registered, an OTP has been sent.",
    });
    return;
  }

  const { otp, expiresAt } = generateOtp(); // e.g., 6-digit
  const hashedOTP = hashToken(otp);

  await prisma.user.update({
    where: { email },
    data: {
      resetToken: hashedOTP,
      resetTokenExpiry: expiresAt, // 10 min
    },
  });

  await sendOtpEmail(email, otp);

  res.status(200).json({
    message: "If the email is registered, an OTP has been sent.",
  });
  return;
};

export const resetPassword = async (req: Request, res: Response) => {
  const { email, otp, newPassword } = req.body;

  const user = await prisma.user.findUnique({ where: { email } });

  if (!user || !user.resetToken || !user.resetTokenExpiry) {
    res.status(400).json({ message: "Invalid request" });
    return;
  }

  const isExpired = user.resetTokenExpiry < new Date();
  const isValid = verifyHashedToken(otp, user.resetToken); // compare hash

  if (!isValid || isExpired) {
    res.status(400).json({ message: "Invalid or expired OTP" });
    return;
  }

  const hashedPassword = await bcrypt.hash(newPassword, 10);

  await prisma.user.update({
    where: { email },
    data: {
      password: hashedPassword,
      resetToken: null,
      resetTokenExpiry: null,
    },
  });

  res.status(200).json({ message: "Password reset successful" });
  return;
};
