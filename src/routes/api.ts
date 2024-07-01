import { createHonoWithBindings } from '../global/fn/createHonoWithBindings';
import postRouter from "./post"
import userRouter from "./user"
const app = createHonoWithBindings()

app.route('/posts',postRouter)
app.route('/users',userRouter)

export default app