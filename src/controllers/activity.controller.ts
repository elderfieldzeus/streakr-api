import { Context } from "hono";
import { AddActivitySchema } from "../models/activity.types";
import { createActivity, getActivityById } from "../services/activity.service";

export const create = async (c: Context) => {
    const body = await c.req.json();
    const activityData = AddActivitySchema.safeParse(body);

    if (!activityData.success) {
        return c.json({ error: activityData.error.errors }, 400);
    }

    try {
        const activity = await createActivity(activityData.data);
        return c.json({ activity }, 201);
    } catch (error: any) {
        return c.json({ error: error.message }, 500);
    }
}

export const getById = async (c: Context) => {
    const param = c.req.param("id");

    if (!param) {
        return c.json({ error: "Activity ID is required" }, 400);
    }

    try {
        const activity = await getActivityById(parseInt(param));
        return c.json({ activity }, 200);
    } catch (error: any) {
        return c.json({ error: error.message }, 500);
    }
}