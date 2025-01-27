import { createHonoWithBindings } from "./global/fn"
import { applyCorsMiddleware } from "./middlewares/cors"
import { applyJwtValidationApi } from "./middlewares/jwt-validation-api"
import authRouter from "./routes/auth"
import apiRouter from "./routes/api"
import debugRouter from "./routes/debug"
const app = createHonoWithBindings()

applyCorsMiddleware(app)
applyJwtValidationApi(app)

app.route("/auth", authRouter)
app.route("/api", apiRouter)
app.route("/debug", debugRouter)

app.get("/", (c) => {
  return c.html("<h1>Welcome To JWT Authentication </h1>")
})

export default app
