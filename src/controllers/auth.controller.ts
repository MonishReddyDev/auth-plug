import { Request, Response } from "express";
import {
  handleLogout,
  handleLogoutAll,
  handleRefreshToken,
  handleUserLogin,
  handleUserRegistration,
} from "../services/auth.service";

export const registerUser = async (
  req: Request,
  res: Response
): Promise<void> => {
  const { result, accessToken, refreshToken, user } =
    await handleUserRegistration(req);

  if (result.status !== 201) {
    res.status(result.status).json({ message: result.message });
    return;
  }

  // ✅ Set refresh token cookie exactly like you had
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
  });

  // ✅ Match your original response format
  res.status(201).json({
    message: "User registered successfully",
    accessToken,
    user,
  });
};

export const loginUser = async (req: Request, res: Response): Promise<void> => {
  const { result, accessToken, refreshToken, user } = await handleUserLogin(
    req
  );

  if (result.status !== 200) {
    res.status(result.status).json({ message: result.message });
    return;
  }

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
  });

  res.status(200).json({
    message: "Login successful",
    accessToken,
    user,
  });
};

export const refreshTokenHandler = async (
  req: Request,
  res: Response
): Promise<void> => {
  const result = await handleRefreshToken(req);

  if (result.status !== 200) {
    res.status(result.status).json({ message: result.message });
    return;
  }

  res.cookie("refreshToken", result.newRefreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
  });

  res.status(200).json({
    accessToken: result.accessToken,
  });
};

export const logoutHandler = async (
  req: Request,
  res: Response
): Promise<void> => {
  const result = await handleLogout(req);

  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  });

  res.status(result.status).json({ message: result.message });
};

export const logoutAllHandler = async (
  req: Request,
  res: Response
): Promise<void> => {
  const result = await handleLogoutAll(req);

  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  });

  res.status(result.status).json({ message: result.message });
};
