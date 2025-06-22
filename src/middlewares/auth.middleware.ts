import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import redis from "../config/redis";
import { error } from "../utils/response.util";
import { logError } from "../utils/logger.util";

const JWT_SECRET = process.env.JWT_SECRET || "access-secret";

interface DecodedUser {
  userId: string;
  role: "USER" | "ADMIN";
  iat: number;
  exp: number;
}

export const verifyToken = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers.authorization;
  const accessToken =
    req.cookies.accessToken || req.headers.authorization?.split(" ")[1];

  // Check blacklist
  const isBlacklisted = await redis.get(`blacklist:${accessToken}`);
  if (isBlacklisted) {
    logError(new Error("Blacklisted JWT used"), req);
    error(res, "Token is blacklisted. Please log in again.", 401);
    return;
  }

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    error(res, "Access token missing or invalid", 401);
    return;
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as DecodedUser;
    req.user = decoded;
    next();
  } catch (err) {
    logError(err, req);
    error(res, "Invalid or expired access token", 401);
    return;
  }
};
