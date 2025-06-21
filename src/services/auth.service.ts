import { Request } from "express";
import bcrypt from "bcryptjs";
import prisma from "../config/prisma";
import { generateOtp } from "../utils/otp.utils";
import { hashToken } from "../utils/hash.util";
import { sendOtpEmail } from "../utils/Email.utils";
import jwt from "jsonwebtoken";
import { generateAccessToken, generateRefreshToken } from "../utils/jwt.utils";

const REFRESH_SECRET = process.env.REFRESH_SECRET!;

export const handleUserRegistration = async (req: Request) => {
  const { email, password, role } = req.body;

  try {
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return {
        result: { status: 409, message: "User with this email already exists" },
        accessToken: "",
        refreshToken: "",
        user: null,
      };
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const { otp, expiresAt } = generateOtp();
    const hashotp = hashToken(otp);

    const newUser = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        role,
        verifyToken: hashotp,
        verifyTokenExpiry: expiresAt,
      },
    });

    await sendOtpEmail(email, otp);

    const accessToken = generateAccessToken(newUser.id, newUser.role);
    const refreshToken = generateRefreshToken(newUser.id);

    await prisma.refreshToken.create({
      data: {
        token: refreshToken,
        userId: newUser.id,
        userAgent: req.headers["user-agent"] || "unknown",
        ipAddress: req.ip,
        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7),
      },
    });

    return {
      result: { status: 201, message: "User registered successfully" },
      accessToken,
      refreshToken,
      user: {
        id: newUser.id,
        email: newUser.email,
        role: newUser.role,
      },
    };
  } catch (error) {
    console.error("[Register Error]", error);
    return {
      result: {
        status: 500,
        message: "Something went wrong while registering",
      },
      accessToken: "",
      refreshToken: "",
      user: null,
    };
  }
};

export const handleUserLogin = async (req: Request) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return {
        result: { status: 401, message: "Invalid email or password" },
        accessToken: "",
        refreshToken: "",
        user: null,
      };
    }

    if (!user.isVerified) {
      return {
        result: {
          status: 403,
          message: "Email not verified. Please verify your email to log in.",
        },
        accessToken: "",
        refreshToken: "",
        user: null,
      };
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return {
        result: { status: 401, message: "Invalid email or password" },
        accessToken: "",
        refreshToken: "",
        user: null,
      };
    }

    const accessToken = generateAccessToken(user.id, user.role);
    const refreshToken = generateRefreshToken(user.id);

    await prisma.refreshToken.create({
      data: {
        token: refreshToken,
        userId: user.id,
        userAgent: req.headers["user-agent"] || "unknown",
        ipAddress: req.ip,
        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7),
      },
    });

    return {
      result: { status: 200, message: "Login successful" },
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    };
  } catch (error) {
    console.error("[Login Error]", error);
    return {
      result: { status: 500, message: "Something went wrong while logging in" },
      accessToken: "",
      refreshToken: "",
      user: null,
    };
  }
};

export const handleRefreshToken = async (req: Request) => {
  try {
    const token = req.cookies.refreshToken;
    if (!token) return { status: 401, message: "Refresh token missing" };

    let decoded: { userId: string };
    try {
      decoded = jwt.verify(token, REFRESH_SECRET) as { userId: string };
    } catch {
      return { status: 401, message: "Invalid or expired refresh token" };
    }

    const storedToken = await prisma.refreshToken.findUnique({
      where: { token },
    });
    if (
      !storedToken ||
      !storedToken.isValid ||
      storedToken.expiresAt < new Date()
    ) {
      return { status: 401, message: "Invalid or expired refresh token" };
    }

    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
    });
    if (!user) return { status: 404, message: "User not found" };

    // Invalidate the old refresh token
    await prisma.refreshToken.update({
      where: { token },
      data: { isValid: false },
    });

    const newRefreshToken = generateRefreshToken(user.id);
    await prisma.refreshToken.create({
      data: {
        token: newRefreshToken,
        userId: user.id,
        userAgent: req.headers["user-agent"] || "unknown",
        ipAddress: req.ip,
        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7),
      },
    });

    const accessToken = generateAccessToken(user.id, user.role);

    return {
      status: 200,
      accessToken,
      newRefreshToken,
    };
  } catch (err) {
    console.error("[Refresh Error]", err);
    return {
      status: 401,
      message: "Something went wrong during token refresh",
    };
  }
};

export const handleLogout = async (req: Request) => {
  try {
    const token = req.cookies.refreshToken;

    if (!token) {
      return {
        status: 200,
        message: "Logged out (no token found)",
      };
    }

    await prisma.refreshToken.updateMany({
      where: { token, isValid: true },
      data: { isValid: false },
    });

    return {
      status: 200,
      message: "Logged out successfully",
    };
  } catch (error) {
    console.error("[Logout Error]", error);
    return {
      status: 500,
      message: "Logout failed",
    };
  }
};

export const handleLogoutAll = async (req: Request) => {
  try {
    const token = req.cookies.refreshToken;

    if (!token) {
      return {
        status: 200,
        message: "Logged out from all devices (no token found)",
      };
    }

    let decoded: { userId: string };
    try {
      decoded = jwt.verify(token, REFRESH_SECRET) as { userId: string };
    } catch {
      return {
        status: 401,
        message: "Invalid or expired token",
      };
    }

    await prisma.refreshToken.updateMany({
      where: { userId: decoded.userId, isValid: true },
      data: { isValid: false },
    });

    return {
      status: 200,
      message: "Logged out from all devices successfully",
    };
  } catch (error) {
    console.error("[Logout-All Error]", error);
    return {
      status: 500,
      message: "Something went wrong while logging out from all devices",
    };
  }
};
