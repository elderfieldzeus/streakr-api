import { Hono } from 'hono'
import { handle } from 'hono/vercel'
import { cors } from 'hono/cors'
import { authRouter } from './routes/auth.route'
import { jwtFilter } from './middlewares/jwt.middleware'
import env from './config/env'

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

app.get('/jwt', jwtFilter, (c) => {
  return c.json({ message: "Authorized." })
});

app.route('/auth', authRouter);

Bun.serve({
  fetch: app.fetch,
  port: env.PORT
})

console.log(`Listening on http://localhost:${env.PORT}`)