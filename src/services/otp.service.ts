import crypto from "crypto";

export function generateOtp(length = 6, expiresInMinutes = 10) {
  const max = Math.pow(10, length);
  const otp = crypto.randomInt(0, max).toString().padStart(length, "0");
  const expiresAt = new Date(Date.now() + expiresInMinutes * 60 * 1000);
  return { otp, expiresAt };
}
