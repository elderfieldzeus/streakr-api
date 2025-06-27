import { Hono } from 'hono'
import { handle } from 'hono/vercel'
import { cors } from 'hono/cors'
import { authRouter } from './routes/auth.route'
import { jwtFilter } from './middlewares/jwt.middleware'
import env from './config/env'
import { userRouter } from './routes/user.route'
import cron from 'node-cron'
import { checkActivityStatus, getAllActivities } from './services/activity.service'
import { activityRouter } from './routes/activity.route'
import { logRouter } from './routes/log.route'

const app = new Hono().basePath('/api')

// Checks the status of activities every day at midnight, resets streak to 0 if no logs are found
cron.schedule('0 0 * * *', async () => {
  const activities = await getAllActivities();

  activities.forEach(async (activity) => {
    try {
      await checkActivityStatus(activity.id);
    } catch (error) {
      console.error(`Error checking activity status for ID ${activity.id}:`, error);
    }
  });
});

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
app.route('/user', userRouter);
app.route('/activity', activityRouter);
app.route('/log', logRouter);

Bun.serve({
  fetch: app.fetch,
  port: env.PORT
})

console.log(`Listening on port ${env.PORT}`)