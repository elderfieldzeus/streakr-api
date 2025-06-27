import { z } from 'zod';

export const AddLogSchema = z.object({
    id: z.number().int('Invalid log ID').positive('Log ID must be a positive integer'),
    date: z.string().datetime('Invalid date format'),
    activity_id: z.number().int('Invalid activity ID').positive('Activity ID must be a positive integer')
});

export const DeleteLogSchema = z.object({
    id: z.number().int('Invalid log ID').positive('Log ID must be a positive integer')
});

export const LogResponseSchema = z.object({
    id: z.number().int('Invalid log ID').positive('Log ID must be a positive integer'),
    date: z.string().datetime('Invalid date format'),
    is_continued: z.boolean().optional(),
    activity_id: z.number().int('Invalid activity ID').positive('Activity ID must be a positive integer'),
    created_at: z.date().optional(),
});

export type AddLogInput = z.infer<typeof AddLogSchema>;
export type DeleteLogInput = z.infer<typeof DeleteLogSchema>;
export type LogResponse = z.infer<typeof LogResponseSchema>;