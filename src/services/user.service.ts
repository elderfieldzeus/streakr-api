import prisma from "../config/prisma";
import { AddUserInput, LoginUserInput, UserResponse, UserResponseSchema } from "../models/user.types";
import * as bcrypt from "bcryptjs";

export const addUser = async (userData: AddUserInput): Promise<UserResponse> => {
    const existingUser = await prisma.user.findFirst({
        where: { email: userData.email }
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
            where: { email }
        });

        if (!user) {
            throw new Error("User not found");
        }

        // Here you would typically compare the hashed password with the provided password
        if (!bcrypt.compareSync(password, user.password)) { // Replace with proper password hashing comparison
            throw new Error("Invalid credentials");
        }

        const retUser = UserResponseSchema.parse(user);

        return retUser;
    }
    catch (error) {
        throw new Error(error instanceof Error ? error.message : "An error occurred during login");
    }
}