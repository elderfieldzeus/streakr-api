import prisma from "../config/prisma";
import { AddUserInput, UserResponse, UserResponseSchema } from "../models/user.types";

export const signUpUser = async (userData: AddUserInput): Promise<UserResponse> => {
    const user = prisma.user.create({
        data: {
            username: userData.username,
            email: userData.email,
            password: userData.password, // Ensure to hash the password before storing it in production
        },
    });

    const retUser = UserResponseSchema.safeParse(await user);

    if (!retUser.success) {
        throw new Error("Invalid user data");
    }

    return retUser.data;
}

export const loginUser = async (email: string, password: string): Promise<UserResponse> => {
    try {
        const user = await prisma.user.findUnique({
            where: { email }
        });

        if (!user) {
            throw new Error("User not found");
        }

        // Here you would typically compare the hashed password with the provided password
        if (user.password !== password) { // Replace with proper password hashing comparison
            throw new Error("Invalid credentials");
        }

        const retUser = UserResponseSchema.safeParse(user);

        if (!retUser.success) {
            throw new Error("Invalid user data");
        }

        return retUser.data;
    }
    catch (error) {
        throw new Error("Login failed");
    }
}