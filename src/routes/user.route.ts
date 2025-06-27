import { Hono } from "hono";
import { remove, update } from "../controllers/user.controller";
import { jwtFilter } from "../middlewares/jwt.middleware";

export const userRouter = new Hono();

userRouter.patch("/:id", jwtFilter, update);
userRouter.delete("/:id", jwtFilter, remove);