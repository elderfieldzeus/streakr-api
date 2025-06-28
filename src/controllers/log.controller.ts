import { Context } from "hono";
import { addLog, deleteLog, getLogById, getLogsByActivityId } from "../services/log.service";

export const create = async (c: Context) => {
    const param = c.req.param("activity_id");

    if (!param) {
        return c.json({ error: "Activity ID is required" }, 400);
    }

    try {
        const log = await addLog(parseInt(param));
        return c.json({ log }, 201);
    } catch (error: any) {
        return c.json({ error: error.message }, 500);
    }
}

export const getById = async (c: Context) => {
    const param = c.req.param("id");

    if (!param) {
        return c.json({ error: "Log ID is required" }, 400);
    }

    try {
        const log = await getLogById(parseInt(param));
        if (!log) {
            return c.json({ error: "Log not found" }, 404);
        }
        return c.json({ log }, 200);
    } catch (error: any) {
        return c.json({ error: error.message }, 500);
    }
}

export const getByActivityId = async (c: Context) => {
    const param = c.req.param("activity_id");

    if (!param) {
        return c.json({ error: "Activity ID is required" }, 400);
    }

    try {
        const logs = await getLogsByActivityId(parseInt(param));
        return c.json({ logs }, 200);
    } catch (error: any) {
        return c.json({ error: error.message }, 500);
    }
}

export const remove = async (c: Context) => {
    const param = c.req.param("id");

    if (!param) {
        return c.json({ error: "Log ID is required" }, 400);
    }

    try {
        const log = await deleteLog(parseInt(param));
        return c.json({ log }, 200);
    } catch (error: any) {
        return c.json({ error: error.message }, 500);
    }
}