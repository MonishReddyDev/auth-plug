import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import swaggerUi from "swagger-ui-express";
import YAML from "yamljs";
import path from "path";
import authRoutes from "./routes/auth.routes";
import protectedRoutes from "./routes/protected.routes";
import Passport from "./config/passport";

dotenv.config();

const app = express();

// Swagger setup **before** your routes
const swaggerDocument = YAML.load(path.join(__dirname, "../openapi.yaml"));
app.use("/api/auth/docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

app.use(
  cors({
    origin: ["http://127.0.0.1:5500", "http://localhost:8000"], // frontend ports
    credentials: true,
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
