import { Hono } from "hono";
import { jwtFilter } from "../middlewares/jwt.middleware";
import { create } from "../controllers/log.controller";

export const logRouter = new Hono();

logRouter.post("/:id", jwtFilter, create);