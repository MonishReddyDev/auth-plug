import { NextFunction, Request, Response } from "express";

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
      res.status(403).json({ message: "Forbidden: Insufficient role" });
      return;
    }
    next();
  };
};
