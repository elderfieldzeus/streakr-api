import { Context } from "hono";
import { AddActivitySchema, UpdateActivitySchema } from "../models/activity.types";
import { createActivity, deleteActivity, getActivityById, getAllPublicActivities, getUserActivities, updateActivity } from "../services/activity.service";

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

export const getAllPublic = async (c: Context) => {
    try {
        const activities = await getAllPublicActivities();
        return c.json({ activities }, 200);
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

export const getByUserId = async (c: Context) => {
    const userId = c.req.param("user_id");
    if (!userId) {
        return c.json({ error: "User ID is required" }, 400);
    }
    try {
        const activities = await getUserActivities(parseInt(userId));
        return c.json({ activities }, 200);
    } catch (error: any) {
        return c.json({ error: error.message }, 500);
    }
}

export const update = async (c: Context) => {
    const param = c.req.param("id");
    const body = await c.req.json();
    const activityData = UpdateActivitySchema.safeParse(body);

    if (!activityData.success) {
        return c.json({ error: activityData.error.errors }, 400);
    }

    if (!param) {
        return c.json({ error: "Activity ID is required" }, 400);
    }

    try {
        const updatedActivity = await updateActivity(parseInt(param), activityData.data);
        return c.json({ activity: updatedActivity }, 200);
    } catch (error: any) {
        return c.json({ error: error.message }, 500);
    }
}

export const remove = async (c: Context) => {
    const param = c.req.param("id");

    if (!param) {
        return c.json({ error: "Activity ID is required" }, 400);
    }

    try {
        const activity = await deleteActivity(parseInt(param));
        return c.json({ activity }, 200);
    } catch (error: any) {
        return c.json({ error: error.message }, 500);
    }
}