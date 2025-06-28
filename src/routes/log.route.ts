import { Hono } from "hono";
import { jwtFilter } from "../middlewares/jwt.middleware";
import { create, getByActivityId, getById, remove } from "../controllers/log.controller";

export const logRouter = new Hono();

logRouter.get("/:id", jwtFilter, getById);
logRouter.get("/activity/:activity_id", jwtFilter, getByActivityId);
logRouter.post("/activity/:activity_id", jwtFilter, create);
logRouter.delete("/:id", jwtFilter, remove);