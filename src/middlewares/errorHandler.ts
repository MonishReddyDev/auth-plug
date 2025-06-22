// src/middlewares/errorHandler.ts
import { error } from "../utils/response.util";
import { logError } from "../utils/logger.util";
import { NextFunction, Request, Response } from "express";

export function errorHandler(
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
) {
  logError(err, req); // Add this line!
  const status = err.status || 500;
  const message = err.message || "Internal Server Error";
  return error(
    res,
    message,
    status,
    process.env.NODE_ENV === "production" ? {} : { stack: err.stack }
  );
}
