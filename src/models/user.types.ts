import { z } from 'zod';

export const AddUserSchema = z.object({
    username: z.string().min(1, 'Username is required'),
    email: z.string().email('Invalid email address'),
    password: z.string().min(6, 'Password must be at least 6 characters')
});

export const LoginUserSchema = z.object({
    email: z.string().email('Invalid email address'),
    password: z.string().min(6, 'Password must be at least 6 characters')
});

export const UpdateUserSchema = z.object({
    username: z.string().min(1, 'Username is required').optional(),
    email: z.string().email('Invalid email address').optional(),
    password: z.string().min(6, 'Password must be at least 6 characters').optional()
});

export const UserResponseSchema = z.object({
    id: z.number().int('Invalid user ID').positive('User ID must be a positive integer'),
    username: z.string(),
    email: z.string().email('Invalid email address'),
    created_at: z.date().optional(),
});

export type AddUserInput = z.infer<typeof AddUserSchema>;
export type LoginUserInput = z.infer<typeof LoginUserSchema>;
export type UpdateUserInput = z.infer<typeof UpdateUserSchema>;
export type UserResponse = z.infer<typeof UserResponseSchema>;