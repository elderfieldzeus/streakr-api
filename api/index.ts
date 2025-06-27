import { Hono } from 'hono'
import { handle } from 'hono/vercel'
import { cors } from 'hono/cors'
import { userRouter } from './routes/user.route'

const app = new Hono().basePath('/api')

app.use('*', cors({
  origin: '*', 
  allowMethods: ['GET', 'POST', 'PATCH', 'DELETE'],
  credentials: true, // Allow credentials
  allowHeaders: ['Content-Type', 'Authorization'],
}))

app.get('/health', (c) => {
  return c.json({ message: "Healthy!" })
})

app.route('/users', userRouter); 

const handler = handle(app);

export const GET = handler;
export const POST = handler;
export const PATCH = handler;
export const DELETE = handler;