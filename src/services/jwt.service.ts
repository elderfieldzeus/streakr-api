import env from "../config/env";
import * as jwt from 'jsonwebtoken';

export const generateJwt = (userId: string): string => {
    return jwt.sign({ id: userId }, env.JWT_SECRET, { expiresIn: '1h' });
}

export const verifyJwt = (token: string): string | jwt.JwtPayload => {
    try {
        return jwt.verify(token, env.JWT_SECRET);
    } catch (error) {
        throw new Error('Invalid or expired token');
    }
}