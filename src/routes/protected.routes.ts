import express from "express";
import { verifyToken } from "../middlewares/auth.middleware";
import { requireRole } from "../middlewares/role.middleware";
import prisma from "../config/prisma";

const router = express.Router();

// ✅ /profile route – any authenticated user can access
router.get("/me", verifyToken, async (req, res) => {
  try {
    const { userId } = req.user as { userId: string; role: string }; // From JWT middleware
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, role: true }, // Add name etc if needed
    });

    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    res.json({ user });
  } catch (e) {
    res.status(500).json({ message: "Internal server error" });
  }
});

// 🔒 /admin route – only ADMINs can access
router.get("/admin", verifyToken, requireRole("ADMIN"), (req, res) => {
  res.json({ message: "Welcome Admin! 🔐" });
});

export default router;
