import prisma from "../config/prisma";

import { hashToken, verifyHashedToken } from "../utils/hash.util";
import bcrypt from "bcryptjs";
import { generateOtp } from "../utils/otp.utils";
import { sendOtpEmail } from "../utils/Email.utils";

export const handleForgotPassword = async (email: string) => {
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    return {
      status: 200,
      message: "If the email is registered, an OTP has been sent.",
    };
  }

  const { otp, expiresAt } = generateOtp();
  const hashedOTP = hashToken(otp);

  await prisma.user.update({
    where: { email },
    data: {
      resetToken: hashedOTP,
      resetTokenExpiry: expiresAt,
    },
  });

  await sendOtpEmail(email, otp);

  return {
    status: 200,
    message: "If the email is registered, an OTP has been sent.",
  };
};

export const handleResetPassword = async (
  email: string,
  otp: string,
  newPassword: string
) => {
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user || !user.resetToken || !user.resetTokenExpiry) {
    return { status: 400, message: "Invalid request" };
  }

  const isExpired = user.resetTokenExpiry < new Date();
  const isValid = verifyHashedToken(otp, user.resetToken);

  if (!isValid || isExpired) {
    return { status: 400, message: "Invalid or expired OTP" };
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

  return { status: 200, message: "Password reset successful" };
};
