import { Request, Response, NextFunction } from "express";

// You can customize this shape if you want more error details
export function globalErrorHandler(
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
) {
  // Default to 500 if not set
  const status = err.status || 500;
  const message = err.message || "Internal Server Error";

  // Optional: Log error stack in non-production
  if (process.env.NODE_ENV !== "production") {
    // eslint-disable-next-line no-console
    console.error("[GLOBAL ERROR]", err);
  }

  // Your consistent error shape
  return res.status(status).json({
    status: "error",
    message,
    data: err.data || {},
  });
}
