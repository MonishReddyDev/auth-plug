import { Response } from "express";

export type CookieType = "refreshToken" | "accessToken";

const cookieSettings: Record<CookieType, object> = {
  refreshToken: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  },
  accessToken: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 15 * 60 * 1000, // 15 minutes
  },
};

export function setAuthCookie(
  res: Response,
  name: CookieType,
  value: string
): void {
  res.cookie(name, value, cookieSettings[name]);
}

export function clearAuthCookie(res: Response, name: CookieType): void {
  res.clearCookie(name, cookieSettings[name]);
}
