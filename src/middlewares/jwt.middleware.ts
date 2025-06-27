import { Context } from "hono";
import { verifyJwt } from "../services/jwt.service";

export const jwtFilter = (c: Context, next: () => Promise<void>) => {
    const token = c.req.header("Authorization")?.replace("Bearer ", "");
    if (!token) {
        return c.json({ error: "Unauthorized" }, 401);
    }
    
    try {
        const decoded = verifyJwt(token);
        c.set("jwtPayload", decoded);
    } catch (error) {
        return c.json({ error: error instanceof Error ? error.message : "Unknown error" }, 401);
    }
    
    // For now, we will just pass the token to the next middleware
    c.set("token", token);
    
    return next();
}