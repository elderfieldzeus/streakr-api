import { Context } from "hono";
import { AddUserSchema, UpdateUserSchema } from "../models/user.types";
import { sign } from "jsonwebtoken";
import { addUser, deleteUser, loginUser, updateUser } from "../services/user.service";
import env from "../config/env";
import { generateJwt } from "../services/jwt.service";

export const signup = async (c: Context) => {
    const body = await c.req.json();
    const userData = AddUserSchema.safeParse(body);

    if (!userData.success) {
        return c.json({ error: userData.error.errors }, 400);
    }

    try {
        const user = await addUser(userData.data);
        const token = generateJwt(user.id.toString());

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
        const token = generateJwt(user.id.toString());

        return c.json({ user, token }, 200);
    } catch (error: any) {
        return c.json({ error: error.message }, 500);
    }
}

export const update = async (c: Context) => {
    const param = c.req.param("id");
    
    if (!param) {
        return c.json({ error: "User ID is required" }, 400);
    }

    const body = await c.req.json();
    const userData = UpdateUserSchema.safeParse(body);

    if (!userData.success) {
        return c.json({ error: userData.error.errors }, 400);
    }

    try {
        // Assuming updateUser is a function that updates the user data
        const updatedUser = await updateUser(parseInt(param), userData.data);
        return c.json({ user: updatedUser }, 200);
    } catch (error: any) {
        return c.json({ error: error.message }, 500);
    }
}

export const remove = async (c: Context) => {
    const param = c.req.param("id");

    if (!param) {
        return c.json({ error: "User ID is required" }, 400);
    }

    try {
        // Assuming deleteUser is a function that deletes the user
        const deletedUser = await deleteUser(parseInt(param));
        return c.json({ user: deletedUser }, 200);
    } catch (error: any) {
        return c.json({ error: error.message }, 500);
    }
}