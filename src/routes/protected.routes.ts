import express from "express";
import { verifyToken } from "../middlewares/auth.middleware";
import { requireRole } from "../middlewares/role.middleware";

const router = express.Router();

// ✅ /profile route – any authenticated user can access
router.get("/profile", verifyToken, (req, res) => {
  res.json({
    message: "You accessed your profile",
    user: req.user,
  });
});

// 🔒 /admin route – only ADMINs can access
router.get("/admin", verifyToken, requireRole("ADMIN"), (req, res) => {
  res.json({ message: "Welcome Admin! 🔐" });
});

export default router;
