import { Hono } from "hono";
import { jwtFilter } from "../middlewares/jwt.middleware";
import { create, getAllPublic, getById, getByUserId, remove, update } from "../controllers/activity.controller";

export const activityRouter = new Hono();

activityRouter.get("/", jwtFilter, getAllPublic);
activityRouter.get("/:id", jwtFilter, getById);
activityRouter.get("/user/:user_id", jwtFilter, getByUserId);
activityRouter.post("/", jwtFilter, create);
activityRouter.patch("/:id", jwtFilter, update);
activityRouter.delete("/:id", jwtFilter, remove);