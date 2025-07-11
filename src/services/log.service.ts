import prisma from "../config/prisma";
import { LogResponse, LogResponseSchema } from "../models/log.types";
import { getActivityById } from "./activity.service";

export const addLog = async (activity_id: number): Promise<LogResponse> => {
    const today = new Date();

    const existingLog = await prisma.log.findFirst({
        where: {
            date: {
                gte: new Date(today.setHours(0, 0, 0, 0)),
                lt: new Date(today.setHours(23, 59, 59, 999)),
            },
            activity_id,
            deleted_at: null,
        },
    });

    if (existingLog) {
        throw new Error("Log for this activity already exists for today");
    }

    const activity = await getActivityById(activity_id);

    if (!activity) {
        throw new Error("Activity not found or has been deleted");
    }

    const newLog = await prisma.log.create({
        data: {
            activity_id: activity_id
        },
    });

    const counter = activity.counter = 1; 

    await prisma.activity.update({
        where: { id: activity.id },
        data: { counter },
    });

    return LogResponseSchema.parse(newLog);
}

export const getLogById = async (logId: number): Promise<LogResponse | null> => {
    const log = await prisma.log.findFirst({
        where: {
            id: logId,
            deleted_at: null,
        },
    });

    if (!log) {
        return null;
    }

    return LogResponseSchema.parse(log);
}

export const getLogsByActivityId = async (activityId: number): Promise<LogResponse[]> => {
    const logs = await prisma.log.findMany({
        where: {
            activity_id: activityId,
            deleted_at: null,
        },
        orderBy: {
            date: 'desc',
        },
    });

    return logs.map((log: unknown) => LogResponseSchema.parse(log));
}

export const deleteLog = async (logId: number): Promise<LogResponse> => {
    const log = await prisma.log.findFirst({
        where: {
            id: logId,
            deleted_at: null,
        },
    });

    if (!log) {
        throw new Error("Log not found or has been deleted");
    }

    const deletedLog = await prisma.log.update({
        where: { id: logId },
        data: { deleted_at: new Date() },
    });

    return LogResponseSchema.parse(deletedLog);
}