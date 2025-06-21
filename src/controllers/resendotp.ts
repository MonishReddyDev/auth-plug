import { Request, Response } from "express";
import prisma from "../config/prisma";
import { generateOtp } from "../services/otp.service";
import { hashToken } from "../utils/hash.util";
import { sendOtpEmail } from "../services/sendEmail.service";

export const resendOtp = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      res
        .status(200)
        .json({ message: "If the email exists, an OTP has been sent" });
      return;
    }

    if (user.isVerified) {
      res.status(400).json({ message: "Email already verified" });
      return;
    }

    // Generate new 6-digit OTP and expiry
    const { otp: rawOtp } = generateOtp(6, 10);
    const hashedOtp = hashToken(rawOtp);

    await prisma.user.update({
      where: { email },
      data: {
        verifyToken: hashedOtp,
        verifyTokenExpiry: new Date(Date.now() + 1000 * 60 * 10), // 10 mins
      },
    });

    // Send OTP again
    await sendOtpEmail(user.email, rawOtp);

    res.status(200).json({ message: "OTP resent successfully" });
    return;
  } catch (err) {
    console.error("[RESEND_OTP_ERROR]", err);
    res.status(500).json({ message: "Something went wrong" });
    return;
  }
};
