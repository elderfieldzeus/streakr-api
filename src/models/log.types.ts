import { z } from 'zod';

export const LogResponseSchema = z.object({
    id: z.number().int('Invalid log ID').positive('Log ID must be a positive integer'),
    date: z.date(),
    activity_id: z.number().int('Invalid activity ID').positive('Activity ID must be a positive integer'),
    created_at: z.date().optional(),
});

export type LogResponse = z.infer<typeof LogResponseSchema>;