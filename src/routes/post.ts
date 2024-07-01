import { createHonoWithBindings } from '../global/fn/createHonoWithBindings';
import { drizzle } from "drizzle-orm/d1"
import { posts } from '../db/schema';

const app = createHonoWithBindings()

app.get("/", async (c) => {
  const db = drizzle(c.env.DB)
  const result = await db.select().from(posts).all()
  return c.json({
    success: true,
    posts: result,
  })
})

export default app