import { Hono } from "hono";
import { signup } from "../controllers/user.controller";

export const userRouter = new Hono();

userRouter.post("/signup", signup);