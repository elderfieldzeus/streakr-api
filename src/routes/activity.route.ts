import { Hono } from "hono";
import { jwtFilter } from "../middlewares/jwt.middleware";
import { create, getById } from "../controllers/activity.controller";

export const activityRouter = new Hono();

activityRouter.post("/", jwtFilter, create);
activityRouter.get("/:id", jwtFilter, getById);