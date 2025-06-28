import prisma from "../config/prisma";
import { generateOtp } from "../utils/otp.utils";
import { hashToken } from "../utils/hash.util";
import { sendOtpEmail } from "../utils/email.utils";
import { logError } from "../utils/logger.util";

export const resendOtpService = async (email: string) => {
  try {
    const user = await prisma.user.findUnique({ where: { email } });

    // Always respond generically to prevent email enumeration
    if (!user) {
      return {
        status: 200,
        message: "If the email exists, an OTP has been sent",
      };
    }

    if (user.isVerified) {
      return { status: 400, message: "Email already verified" };
    }

    const { otp: rawOtp } = generateOtp(6, 10); // 6-digit, 10 minutes
    const hashedOtp = hashToken(rawOtp);

    await prisma.user.update({
      where: { email },
      data: {
        verifyToken: hashedOtp,
        verifyTokenExpiry: new Date(Date.now() + 1000 * 60 * 10),
      },
    });

    sendOtpEmail(user.email, rawOtp).catch((err) => logError(err));

    return { status: 200, message: "OTP resent successfully" };
  } catch (err) {
    console.error("[RESEND_OTP_SERVICE_ERROR]", err);
    return { status: 500, message: "Something went wrong" };
  }
};

export const verifyOtpService = async (email: string, otp: string) => {
  try {
    const hashedOTP = hashToken(otp);

    const user = await prisma.user.findFirst({
      where: {
        email,
        verifyToken: hashedOTP,
        verifyTokenExpiry: { gte: new Date() },
      },
    });

    if (!user) {
      return { status: 400, message: "Invalid or expired OTP" };
    }

    await prisma.user.update({
      where: { email },
      data: {
        isVerified: true,
        verifyToken: null,
        verifyTokenExpiry: null,
      },
    });

    return { status: 200, message: "Email verified successfully" };
  } catch (error) {
    console.error("[VERIFY_OTP_ERROR]", error);
    return { status: 500, message: "Internal server error" };
  }
};
