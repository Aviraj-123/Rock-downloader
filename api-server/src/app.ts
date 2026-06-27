import express, { type Express, type Request, type Response, type NextFunction } from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import pinoHttp from "pino-http";
import { randomUUID } from "crypto";
import router from "./routes";
import { logger } from "./lib/logger";

const app: Express = express();

app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req) {
        return {
          id: req.id,
          method: req.method,
          url: req.url?.split("?")[0],
        };
      },
      res(res) {
        return {
          statusCode: res.statusCode,
        };
      },
    },
  }),
);

app.use(cors({
  origin: true,
  credentials: true,
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Assign anonymous user token — persists across sessions until cookie expires (90 days)
app.use((req: Request, res: Response, next: NextFunction) => {
  let token = req.cookies?.["rd_user"] as string | undefined;
  if (!token || token.length < 20) {
    token = randomUUID();
    res.cookie("rd_user", token, {
      maxAge: 90 * 24 * 60 * 60 * 1000, // 90 days
      httpOnly: true,
      sameSite: "lax",
    });
  }
  (req as any).userToken = token;
  next();
});

app.use("/api", router);

export default app;
