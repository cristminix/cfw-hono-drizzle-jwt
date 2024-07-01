import { createHonoWithBindings } from '../global/fn/createHonoWithBindings';
import { drizzle } from "drizzle-orm/d1"
import { users } from '../db/schema';

const app = createHonoWithBindings()

app.get("/", async (c) => {
  const db = drizzle(c.env.DB)
  const result = await db
    .select({
      id: users.id,
      username: users.username,
      email: users.email,
    })
    .from(users)
    .all()
  return c.json({
    success: true,
    users: result,
  })
})

export default app