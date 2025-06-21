import prisma from "../config/prisma";
import { Response, Request } from "express";
import { hashToken } from "../utils/hash.util";

export const verifyOtp = async (req: Request, res: Response) => {
  try {
    const { email, otp } = req.body;
    const hashedOTP = hashToken(otp);

    const user = await prisma.user.findFirst({
      where: {
        email,
        verifyToken: hashedOTP,
        verifyTokenExpiry: {
          gte: new Date(),
        },
      },
    });

    if (!user) {
      res.status(400).json({ message: "Invalid or expired OTP" });
      return;
    }

    // 4. Mark user as verified and clear OTP
    await prisma.user.update({
      where: { email },
      data: {
        isVerified: true,
        verifyToken: null,
        verifyTokenExpiry: null,
      },
    });
    res.status(200).json({ message: "Email verified successfully" });
    return;
  } catch (error) {
    console.error("[Verify OTP Error]", error);
    res.status(500).json({ message: "Internal server error" });
    return;
  }
};
