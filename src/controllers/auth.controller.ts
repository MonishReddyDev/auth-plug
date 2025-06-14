import { Request, Response } from "express";
import prisma from "../config/prisma";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import {
  generateAccessToken,
  generateRefreshToken,
} from "../services/token.service";

// Use environment variable for refresh token secret, fallback to a dev default
const REFRESH_SECRET = process.env.REFRESH_SECRET || "refresh-secret";

/**
 * Registers a new user.
 * - Checks for existing user by email.
 * - Hashes password with bcrypt.
 * - Creates user in database.
 * - Generates access and refresh tokens.
 * - Stores refresh token in DB with metadata.
 * - Sets refresh token in secure, HTTP-only cookie.
 */
export const register = async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body;

  try {
    // 1. Check if user already exists
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      res.status(409).json({ message: "User with this email already exists" });
      return;
    }

    // 2. Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 3. Create new user in DB
    const newUser = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        // Other fields (isVerified, role, etc.) use defaults
      },
    });

    // 4. Generate access & refresh tokens
    const accessToken = generateAccessToken(newUser.id, newUser.role);
    const refreshToken = generateRefreshToken(newUser.id);

    // 5. Store refresh token in DB with metadata
    await prisma.refreshToken.create({
      data: {
        token: refreshToken,
        userId: newUser.id,
        userAgent: req.headers["user-agent"] || "unknown",
        ipAddress: req.ip,
        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7), // 7 days
        // isValid defaults to true
      },
    });

    // 6. Set refresh token in secure HTTP-only cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true, // Prevents JS access to the cookie
      secure: true, // Cookie sent only on HTTPS
      sameSite: "strict", // Prevents CSRF
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    });

    // 7. Respond with success (never send password!)
    res.status(201).json({
      message: "User registered successfully",
      accessToken,
      user: {
        id: newUser.id,
        email: newUser.email,
        role: newUser.role,
      },
    });
    return;
  } catch (error) {
    console.error("[Register Error]", error);
    res.status(500).json({ message: "Something went wrong while registering" });
    return;
  }
};

/**
 * Logs in a user.
 * - Finds user by email.
 * - Verifies password.
 * - Generates new access and refresh tokens.
 * - Stores refresh token in DB.
 * - Sets refresh token in secure, HTTP-only cookie.
 */
export const login = async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body;

  try {
    // 1. Find user by email
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      res.status(401).json({ message: "Invalid email or password" });
      return;
    }

    // 2. Compare provided password with stored hash
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      res.status(401).json({ message: "Invalid email or password" });
      return;
    }

    // 3. Generate tokens
    const accessToken = generateAccessToken(user.id, user.role);
    const refreshToken = generateRefreshToken(user.id);

    // 4. Store refresh token in DB
    await prisma.refreshToken.create({
      data: {
        token: refreshToken,
        userId: user.id,
        userAgent: req.headers["user-agent"] || "unknown",
        ipAddress: req.ip,
        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7), // 7 days
        // isValid defaults to true
      },
    });

    // 5. Set refreshToken in a secure HttpOnly cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    });

    // 6. Return access token and user info
    res.status(200).json({
      message: "Login successful",
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    });
    return;
  } catch (error) {
    console.error("[Login Error]", error);
    res.status(500).json({ message: "Something went wrong while logging in" });
    return;
  }
};

/**
 * Rotates and refreshes access token using a valid refresh token.
 * - Verifies refresh token signature and validity.
 * - Invalidates the used refresh token in DB.
 * - Issues new refresh token, stores in DB, and sets in cookie.
 * - Issues new access token and returns to client.
 */
export const refreshAccessToken = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    // 1. Get refresh token from cookie
    const token = req.cookies.refreshToken;
    if (!token) {
      res.status(401).json({ message: "Refresh token missing" });
      return;
    }

    // 2. Verify the refresh token using secret
    let decoded: { userId: string };
    try {
      decoded = jwt.verify(token, REFRESH_SECRET) as { userId: string };
    } catch {
      res.status(401).json({ message: "Invalid or expired refresh token" });
      return;
    }

    // 3. Ensure the token exists in DB and is valid
    const storedToken = await prisma.refreshToken.findUnique({
      where: { token },
    });
    if (
      !storedToken ||
      !storedToken.isValid ||
      storedToken.expiresAt < new Date()
    ) {
      res.status(401).json({ message: "Invalid or expired refresh token" });
      return;
    }

    // 4. Get the user by ID from decoded token
    const user = await prisma.user.findUnique({
      where: {
        id: decoded.userId,
      },
    });
    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    // 5. Rotate refresh token: Invalidate old, create new
    await prisma.refreshToken.update({
      where: { token },
      data: { isValid: false },
    });

    // 6. Generate new refresh token and store in DB
    const newRefreshToken = generateRefreshToken(user.id);
    await prisma.refreshToken.create({
      data: {
        token: newRefreshToken,
        userId: user.id,
        userAgent: req.headers["user-agent"] || "unknown",
        ipAddress: req.ip,
        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7), // 7 days
        isValid: true,
      },
    });

    // 7. Generate new access token
    const newAccessToken = generateAccessToken(user.id, user.role);

    // 8. Set new refresh token in cookie
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    });

    // 9. Return new access token to client
    res.status(200).json({
      accessToken: newAccessToken,
    });
    return;
  } catch (error) {
    console.error("[Refresh Error]", error);
    res.status(401).json({ message: "Invalid or expired token" });
    return;
  }
};

/**
 * Logs out a user on the current device/session.
 * - Invalidates the refresh token in the DB.
 * - Clears the refresh token cookie.
 */
export const logout = async (req: Request, res: Response) => {
  try {
    // 1. Get refresh token from cookie
    const token = req.cookies.refreshToken;
    if (!token) {
      res.clearCookie("refreshToken", {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
      });
      res.status(200).json({ message: "Logged out (no token found)" });
      return;
    }

    // 2. Invalidate token in DB
    await prisma.refreshToken.updateMany({
      where: { token, isValid: true },
      data: { isValid: false },
    });

    // 3. Clear the cookie
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });

    // 4. Respond with success
    res.status(200).json({ message: "Logged out successfully" });
    return;
  } catch (error) {
    console.error("[Logout Error]", error);
    res.status(500).json({ message: "Logout failed" });
  }
};

/**
 * Logs out from all devices/sessions.
 * - Decodes refresh token to extract user ID.
 * - Invalidates all refresh tokens for the user in DB.
 * - Clears refresh token cookie in the current device.
 */
export const logoutAll = async (req: Request, res: Response): Promise<void> => {
  try {
    // 1. Get refresh token from cookie
    const token = req.cookies.refreshToken;

    if (!token) {
      res.clearCookie("refreshToken", {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
      });
      res
        .status(200)
        .json({ message: "Logged out from all devices (no token found)" });
      return;
    }

    // 2. Decode token to get user ID (to avoid spoofing)
    let decoded: { userId: string };
    try {
      decoded = jwt.verify(token, REFRESH_SECRET) as { userId: string };
    } catch {
      res.clearCookie("refreshToken", {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
      });
      res.status(401).json({ message: "Invalid or expired token" });
      return;
    }

    // 3. Invalidate all tokens for the user in DB
    await prisma.refreshToken.updateMany({
      where: {
        userId: decoded.userId,
        isValid: true,
      },
      data: {
        isValid: false,
      },
    });

    // 4. Clear cookie on this device too
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });

    // 5. Respond with success
    res
      .status(200)
      .json({ message: "Logged out from all devices successfully" });
    return;
  } catch (error) {
    console.error("[Logout-All Error]", error);
    res.status(500).json({
      message: "Something went wrong while logging out from all devices",
    });
    return;
  }
};
