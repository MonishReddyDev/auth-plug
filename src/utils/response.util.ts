// src/utils/response.util.ts

import { Response } from "express";

export function success(
  res: Response,
  message: string,
  data: any = {},
  status: number = 200
) {
  return res.status(status).json({
    status: "success",
    message,
    data,
  });
}

export function error(
  res: Response,
  message: string,
  status: number = 400,
  data: any = {}
) {
  return res.status(status).json({
    status: "error",
    message,
    data,
  });
}
