import { z } from "zod";

const AddActivitySchema = z.object({
    name: z.string().min(1, 'Activity name is required'),
    description: z.string().optional(),
    is_private: z.boolean().optional(),
    user_id: z.number().int('Invalid user ID').positive('User ID must be a positive integer')
});

const UpdateActivitySchema = z.object({
    id: z.number().int('Invalid activity ID').positive('Activity ID must be a positive integer'),
    name: z.string().min(1, 'Activity name is required').optional(),
    is_private: z.boolean().optional(),
    description: z.string().optional(),
    user_id: z.number().int('Invalid user ID').positive('User ID must be a positive integer').optional()
});

const DeleteActivitySchema = z.object({
    id: z.number().int('Invalid activity ID').positive('Activity ID must be a positive integer')
});

const ActivityResponseSchema = z.object({
    id: z.number().int('Invalid activity ID').positive('Activity ID must be a positive integer'),
    name: z.string(),
    counter: z.number().int('Counter must be an integer').nonnegative('Counter cannot be negative'),
    is_private: z.boolean().optional(),
    user_id: z.number().int('Invalid user ID').positive('User ID must be a positive integer'),
    description: z.string().optional(),
    created_at: z.date().optional(),
});

export type AddActivityInput = z.infer<typeof AddActivitySchema>;
export type UpdateActivityInput = z.infer<typeof UpdateActivitySchema>;
export type DeleteActivityInput = z.infer<typeof DeleteActivitySchema>;
export type ActivityResponse = z.infer<typeof ActivityResponseSchema>;
