import prisma from "../config/prisma";
import { AddUserInput, LoginUserInput, UpdateUserInput, UserResponse, UserResponseSchema } from "../models/user.types";
import * as bcrypt from "bcryptjs";

export const addUser = async (userData: AddUserInput): Promise<UserResponse> => {
    const existingUser = await prisma.user.findFirst({
        where: { 
            email: userData.email,
            deleted_at: null
        }
    });

    if (existingUser) {
        throw new Error("User with this email already exists");
    }

    const hashedPassword = bcrypt.hashSync(userData.password, 10); // Hash the password before storing it

    const user = prisma.user.create({
        data: {
            username: userData.username,
            email: userData.email,
            password: hashedPassword, // Ensure to hash the password before storing it in production
        },
    });

    const retUser = UserResponseSchema.parse(await user);

    return retUser;
}

export const loginUser = async (userData: LoginUserInput): Promise<UserResponse> => {
    const { email, password } = userData;
    
    try {
        const user = await prisma.user.findFirst({
            where: { 
                email,
                deleted_at: null
            }
        });

        if (!user || user.password == null || !bcrypt.compareSync(password, user.password)) { // Replace with proper password hashing comparison
            throw new Error("Invalid credentials");
        }

        const retUser = UserResponseSchema.parse(user);

        return retUser;
    }
    catch (error) {
        throw new Error(error instanceof Error ? error.message : "An error occurred during login");
    }
}

export const getUserById = async (userId: number): Promise<UserResponse | null> => {
    const user = await prisma.user.findFirst({
        where: {
            id: userId,
            deleted_at: null
        }
    });
    if (!user) {
        return null;
    }
    return UserResponseSchema.parse(user);
}

export const updateUser = async (userId: number, userData: UpdateUserInput): Promise<UserResponse> => {
    const hashedPassword = userData.password ? bcrypt.hashSync(userData.password, 10) : undefined;

    const user = await prisma.user.update({
        where: { id: userId },
        data: {
            ...userData,
            ...(hashedPassword ? { password: hashedPassword } : {}),
        }
    });

    const retUser = UserResponseSchema.parse(user);

    return retUser;
}

export const deleteUser = async (userId: number): Promise<UserResponse> => {
    const user = await prisma.user.update({
        where: { id: userId },
        data: { deleted_at: new Date() }, // Soft delete
    });

    if (!user) {
        throw new Error("User not found");
    }

    const retUser = UserResponseSchema.parse(user);

    return retUser;
}