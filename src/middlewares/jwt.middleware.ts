import { Context } from "hono";
import { verifyJwt } from "../services/jwt.service";

export const jwtFilter = (c: Context, next: () => Promise<void>) => {
    const token = c.req.header("Authorization")?.replace("Bearer ", "");
    if (!token) {
        return c.json({ error: "Unauthorized" }, 401);
    }
    
    verifyJwt(token);
    
    // For now, we will just pass the token to the next middleware
    c.set("token", token);
    
    return next();
}