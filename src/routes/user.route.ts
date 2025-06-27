import { Hono } from "hono";
import { remove, update } from "../controllers/user.controller";
import { jwtFilter } from "../middlewares/jwt.middleware";

export const userRouter = new Hono();

userRouter.patch("/edit/:id", jwtFilter, update);
userRouter.delete("/delete/:id", jwtFilter, remove);