import { Request } from "express";
import bcrypt from "bcryptjs";
import prisma from "../config/prisma";
import { generateOtp } from "../utils/otp.utils";
import { hashToken } from "../utils/hash.util";
import { sendOtpEmail } from "../utils/email.utils";
import jwt from "jsonwebtoken";
import { generateAccessToken, generateRefreshToken } from "../utils/jwt.utils";
import redis from "../config/redis";
import { logError } from "../utils/logger.util";
import { blacklistAccessToken } from "../utils/blacklist.utils";

const REFRESH_SECRET = process.env.REFRESH_SECRET!;

export const handleUserRegistration = async (req: Request) => {
  const { email, password, role } = req.body;

  try {
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return {
        status: 409,
        message: "User with this email already exists",
        data: {},
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

    try {
      await sendOtpEmail(email, otp);
    } catch (error) {
      logError(error, req);
    }

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
      status: 201,
      message: "User registered successfully",
      data: {
        user: {
          id: newUser.id,
          email: newUser.email,
          role: newUser.role,
        },
        accessToken,
        refreshToken,
      },
    };
  } catch (error) {
    logError(error, req);
    return {
      status: 500,
      message: "Something went wrong while registering",
      data: {},
    };
  }
};

export const handleUserLogin = async (req: Request) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return {
        status: 401,
        message: "Invalid email or password",
        data: {},
      };
    }

    if (!user.isVerified) {
      return {
        status: 403,
        message: "Email not verified. Please verify your email to log in.",
        data: {},
      };
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return {
        status: 401,
        message: "Invalid email or password",
        data: {},
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
      status: 200,
      message: "Login successful",
      data: {
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
        },
        accessToken,
        refreshToken,
      },
    };
  } catch (error) {
    logError(error, req);
    return {
      status: 500,
      message: "Something went wrong while logging in",
      data: {},
    };
  }
};

export const handleRefreshToken = async (req: Request) => {
  try {
    const token = req.cookies.refreshToken;
    if (!token)
      return { status: 401, message: "Refresh token missing", data: {} };

    let decoded: { userId: string };
    try {
      decoded = jwt.verify(token, REFRESH_SECRET) as { userId: string };
    } catch (err) {
      logError(err, req);
      return {
        status: 401,
        message: "Invalid or expired refresh token",
        data: {},
      };
    }

    const storedToken = await prisma.refreshToken.findUnique({
      where: { token },
    });
    if (
      !storedToken ||
      !storedToken.isValid ||
      storedToken.expiresAt < new Date()
    ) {
      return {
        status: 401,
        message: "Invalid or expired refresh token",
        data: {},
      };
    }

    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
    });
    if (!user) return { status: 404, message: "User not found", data: {} };

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
      message: "Token refreshed",
      data: {
        accessToken,
        refreshToken: newRefreshToken,
      },
    };
  } catch (err) {
    logError(err, req);
    return {
      status: 500,
      message: "Something went wrong during token refresh",
      data: {},
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
        data: {},
      };
    }
    const accessToken =
      req.cookies.accessToken ||
      (req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer ")
        ? req.headers.authorization.split(" ")[1]
        : null);

    // Use the helper for blacklisting
    if (accessToken) {
      await blacklistAccessToken(accessToken);
    }
    await prisma.refreshToken.updateMany({
      where: { token, isValid: true },
      data: { isValid: false },
    });

    return {
      status: 200,
      message: "Logged out successfully",
      data: {},
    };
  } catch (error) {
    logError(error, req);
    return {
      status: 500,
      message: "Logout failed",
      data: {},
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
        data: {},
      };
    }

    let decoded: { userId: string };
    try {
      decoded = jwt.verify(token, REFRESH_SECRET) as { userId: string };
    } catch (err) {
      logError(err, req);
      return {
        status: 401,
        message: "Invalid or expired token",
        data: {},
      };
    }

    await prisma.refreshToken.updateMany({
      where: { userId: decoded.userId, isValid: true },
      data: { isValid: false },
    });

    return {
      status: 200,
      message: "Logged out from all devices successfully",
      data: {},
    };
  } catch (error) {
    logError(error, req);
    return {
      status: 500,
      message: "Something went wrong while logging out from all devices",
      data: {},
    };
  }
};
