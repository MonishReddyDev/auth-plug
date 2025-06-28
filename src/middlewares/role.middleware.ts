import { NextFunction, Request, Response } from "express";
import { error } from "../utils/response.util";

interface UserWithRole {
  userId: string;
  role: "USER" | "ADMIN";
  iat: number;
  exp: number;
}

export const requireRole = (role: "ADMIN" | "USER") => {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = req.user as UserWithRole | undefined;
    if (!user || user.role !== role) {
      error(res, "Forbidden: Insufficient role", 403);
      return;
    }
    next();
  };
};
