import jwt from "jsonwebtoken";
import redis from "../config/redis";

/**
 * Blacklists a JWT access token by storing it in Redis with TTL matching its expiry.
 * @param accessToken The JWT access token to blacklist
 */
export const blacklistAccessToken = async (accessToken: string) => {
  if (!accessToken) return;

  try {
    const decoded = jwt.decode(accessToken) as { exp?: number } | null;
    if (decoded && decoded.exp) {
      const ttl = decoded.exp - Math.floor(Date.now() / 1000);
      if (ttl > 0) {
        await redis.set(`blacklist:${accessToken}`, "true", "EX", ttl);
      }
    }
  } catch (err) {
    // Optionally log error here if you want
  }
};
