// src/middlewares/validateRequest.ts
import { Request, Response, NextFunction } from "express";
import { ObjectSchema } from "joi";
import { error as errorResponse } from "../utils/response.util";
import { logError } from "../utils/logger.util"; // If you want to log validation errors

export const validateRequest = (schema: ObjectSchema) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const { error } = schema.validate(req.body, { abortEarly: false });

    if (error) {
      const errorMessages = error.details.map((detail) => detail.message);

      // Optionally log the validation error for debugging
      logError({ message: "Validation error", details: errorMessages }, req);

      errorResponse(res, "Validation failed", 400, {
        errors: errorMessages,
      });
      return;
    }

    next();
  };
};
