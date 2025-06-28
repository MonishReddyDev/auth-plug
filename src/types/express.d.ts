import "express"; // <-- Correct import for declaration merging


declare global {
  namespace Express {
    interface Request {
      user?: {
        userId: string;
        role: "USER" | "ADMIN";
        iat: number;
        exp: number;
      };
    }
  }
}
