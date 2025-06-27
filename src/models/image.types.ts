import { z } from 'zod';

export const AddImageSchema = z.object({
    id: z.number().int('Invalid image ID').positive('Image ID must be a positive integer'),
    name: z.string().min(1, 'Image name is required'),
    url: z.string().url('Invalid URL format'),
    log_id: z.number().int('Invalid log ID').positive('Log ID must be a positive integer')
});

export const ImageResponseSchema = z.object({
    id: z.number().int('Invalid image ID').positive('Image ID must be a positive integer'),
    name: z.string(),
    url: z.string().url('Invalid URL format'),
    log_id: z.number().int('Invalid log ID').positive('Log ID must be a positive integer'),
    created_at: z.date().optional(),
});

export type AddImageInput = z.infer<typeof AddImageSchema>;
export type ImageResponse = z.infer<typeof ImageResponseSchema>;