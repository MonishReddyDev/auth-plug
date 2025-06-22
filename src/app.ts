import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import authRoutes from "./routes/auth.routes";
import protectedRoutes from "./routes/protected.routes";
import Passport from "./config/passport";

dotenv.config();

const app = express();
app.use(
  cors({
    origin: ["http://127.0.0.1:5500", "http://localhost:8000"], // <-- your frontend port
    credentials: true, // allows cookies
  })
);
app.use(express.json());
app.use(helmet());
app.use(morgan("dev"));
app.use(cookieParser());

app.get("/ping", (req, res) => {
  res.json("Auth-Plug is live");
});

app.use(Passport.initialize());
app.use("/api/auth", authRoutes);
app.use("/api/user", protectedRoutes);

export default app;
