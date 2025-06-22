import { Request, Response } from "express";
import {
  handleLogout,
  handleLogoutAll,
  handleRefreshToken,
  handleUserLogin,
  handleUserRegistration,
} from "../services/auth.service";
import { issueTokensForUser } from "../utils/jwt.utils";
import { success, error } from "../utils/response.util";
import { logError } from "../utils/logger.util";
import { clearAuthCookie, setAuthCookie } from "../utils/cookie.util";

// REGISTER
export const registerUser = async (
  req: Request,
  res: Response
): Promise<void> => {
  const result = await handleUserRegistration(req);

  if (result.status !== 201) {
    logError(new Error(result.message), req);
    error(res, result.message, result.status);
    return;
  }

  // Set refresh token as cookie if needed
  if (result.data.refreshToken) {
    res.cookie("refreshToken", result.data.refreshToken, {
      httpOnly: true, // JS can't access: prevents XSS
      secure: process.env.NODE_ENV === "production", // Use true in production (HTTPS)
      sameSite: "lax", // Strict is safest (Lax if you want, but strict is best for auth)
      path: "/", // Applies to all routes
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    });
  }

  success(res, result.message, result.data, result.status);
  return;
};

// LOGIN
export const loginUser = async (req: Request, res: Response): Promise<void> => {
  const result = await handleUserLogin(req);

  if (result.status !== 200) {
    logError(new Error(result.message), req);
    error(res, result.message, result.status);
    return;
  }

  if (result.data.refreshToken)
    setAuthCookie(res, "refreshToken", result.data.refreshToken);
  // if (result.data.accessToken)
  //   setAuthCookie(res, "accessToken", result.data.accessToken);

  success(res, result.message, result.data, result.status);
};

// REFRESH TOKEN
export const refreshTokenHandler = async (
  req: Request,
  res: Response
): Promise<void> => {
  const result = await handleRefreshToken(req);

  if (result.status !== 200) {
    error(res, result.message, result.status);
    return;
  }

  if (result.data.accessToken) {
    setAuthCookie(res, "accessToken", result.data.accessToken);
  }
  if (result.data.refreshToken) {
    setAuthCookie(res, "refreshToken", result.data.refreshToken);
  }

  success(res, result.message, result.data, result.status);
  return;
};

// LOGOUT
export const logoutHandler = async (
  req: Request,
  res: Response
): Promise<void> => {
  const result = await handleLogout(req);

  clearAuthCookie(res, "accessToken");
  clearAuthCookie(res, "refreshToken");

  if (result.status !== 200) {
    error(res, result.message, result.status);
    return;
  }

  success(res, result.message, result.data, result.status);
  return;
};

// LOGOUT ALL DEVICES
export const logoutAllHandler = async (
  req: Request,
  res: Response
): Promise<void> => {
  const result = await handleLogoutAll(req);

  clearAuthCookie(res, "refreshToken");
  if (result.status !== 200) {
    error(res, result.message, result.status);
    return;
  }

  success(res, result.message, result.data, result.status);
  return;
};

// GOOGLE OAUTH CALLBACK
export const googleCallback = async (req: Request, res: Response) => {
  const user = req.user as any;
  const { accessToken, refreshToken } = issueTokensForUser(user);

  // Set cookies
  res;
  setAuthCookie(res, "accessToken", accessToken);
  setAuthCookie(res, "refreshToken", refreshToken);

  // Consistent response
  success(res, "Google login successful!", {
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      provider: user.provider,
    },
  });
  return;
};

// GITHUB OAUTH CALLBACK (same pattern)
export const githubCallback = async (req: Request, res: Response) => {
  const user = req.user as any;
  const { accessToken, refreshToken } = issueTokensForUser(user);

  setAuthCookie(res, "accessToken", accessToken);
  setAuthCookie(res, "refreshToken", refreshToken);

  success(res, "GitHub login successful!", {
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      provider: user.provider,
    },
  });
  return;
};
