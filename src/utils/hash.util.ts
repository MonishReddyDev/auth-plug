import crypto from "crypto";

export const hashToken = (token: string): string => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

export const verifyHashedToken = (raw: string, hashed: string) => {
  return hashToken(raw) === hashed;
};
