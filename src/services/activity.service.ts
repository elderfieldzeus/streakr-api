import prisma from "../config/prisma";
import { ActivityResponse, ActivityResponseSchema, AddActivityInput, UpdateActivityInput } from "../models/activity.types";
import { getUserById } from "./user.service";

export const checkActivityStatus = async (activity_id: number): Promise<ActivityResponse> => {
    let activity = await prisma.activity.findFirst({
        where: {
            id: activity_id,
            deleted_at: null,
        },
    });

    if (!activity) {
        throw new Error("Activity not found or has been deleted");
    }

    const yesterday = new Date(Date.now() - 1000 * 60 * 60 * 24);

    const yesterdaysLog = await prisma.log.findFirst({
        where: {
            activity_id: activity.id,
            date: {
                gte: yesterday,
                lt: new Date()
            },
            deleted_at: null,
        },
        orderBy: {
            date: 'asc',
        },
    });

    if (!yesterdaysLog) {
        activity = await prisma.activity.update({
            where: { id: activity.id },
            data: { counter: 0 },
        });
    }

    return ActivityResponseSchema.parse(activity);
}

export const createActivity = async (activityData: AddActivityInput): Promise<ActivityResponse> => {
    const user = await getUserById(activityData.user_id);

    if (!user) {
        throw new Error("User not found");
    }

    const activity = await prisma.activity.create({
        data: {
            name: activityData.name,
            description: activityData.description,
            is_private: activityData.is_private,
            counter: 0,
            user_id: activityData.user_id,
        },
    });

    return ActivityResponseSchema.parse(activity);
}

export const getActivityById = async (activityId: number): Promise<ActivityResponse | null> => {
    const activity = await prisma.activity.findFirst({
        where: {
            id: activityId,
            deleted_at: null,
        },
    });
    if (!activity) {
        return null;
    }
    return ActivityResponseSchema.parse(activity);
}

export const getUserActivities = async (userId: number): Promise<ActivityResponse[]> => {
    const activities = await prisma.activity.findMany({
        where: {
            user_id: userId,
            deleted_at: null,
        },
        orderBy: {
            created_at: 'desc',
        },
    });

    return activities.map((activity: unknown) => ActivityResponseSchema.parse(activity));
}

export const getAllActivities = async (): Promise<ActivityResponse[]> => {
    const activities = await prisma.activity.findMany({
        where: {
            deleted_at: null,
        },
        orderBy: {
            created_at: 'desc',
        },
    });
    
    return activities.map((activity: unknown) => ActivityResponseSchema.parse(activity));
}

export const getAllPublicActivities = async (): Promise<ActivityResponse[]> => {
    const activities = await prisma.activity.findMany({
        where: {
            is_private: false,
            deleted_at: null,
        },
        orderBy: {
            created_at: 'desc',
        },
    });

    const retActivities: ActivityResponse[] = activities.map((activity: unknown) => ActivityResponseSchema.parse(activity));

    return retActivities.filter(activity => {
        const user = getUserById(activity.user_id);

        return user !== null;
    });
}

export const updateActivity = async (activityId: number, activityData: UpdateActivityInput): Promise<ActivityResponse> => {
    const activity = await prisma.activity.update({
        where: { id: activityId },
        data: activityData,
    });

    return ActivityResponseSchema.parse(activity);
}

export const deleteActivity = async (activityId: number): Promise<ActivityResponse> => {
    const activity = await prisma.activity.update({
        where: { id: activityId },
        data: { deleted_at: new Date() },
    });

    return ActivityResponseSchema.parse(activity);
}