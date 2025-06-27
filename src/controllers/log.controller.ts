import { Context } from "hono";
import { addLog } from "../services/log.service";

export const create = async (c: Context) => {
    const param = c.req.param("id");

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