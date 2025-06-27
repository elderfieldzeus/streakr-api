import { Context } from "hono";
import { AddUserSchema } from "../models/user.types";
import { sign } from "jsonwebtoken";
import { addUser, loginUser } from "../services/user.service";
import env from "../config/env";

export const signup = async (c: Context) => {
    const body = await c.req.json();
    const userData = AddUserSchema.safeParse(body);

    if (!userData.success) {
        return c.json({ error: userData.error.errors }, 400);
    }

    try {
        const user = await addUser(userData.data);
        const token = sign({ id: user.id }, env.JWT_SECRET);

        return c.json({ user, token }, 201);
    } catch (error: any) {
        return c.json({ error: error.message }, 500);
    }
}

export const login = async (c: Context) => {
    const body = await c.req.json();
    const userData = AddUserSchema.safeParse(body);

    if (!userData.success) {
        return c.json({ error: userData.error.errors }, 400);
    }

    try {
        const user = await loginUser(userData.data); // Assuming addUser can handle login logic
        const token = sign({ id: user.id }, env.JWT_SECRET);

        return c.json({ user, token }, 200);
    } catch (error: any) {
        return c.json({ error: error.message }, 500);
    }
}