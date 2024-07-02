import { cors } from "hono/cors";
export function applyCorsMiddleware(app) {
	app.use("*", (c, next) => {
		const origins =
			c.env.ALLOWED_ORIGINS == "*"
				? "*"
				: c.env.ALLOWED_ORIGINS.split(",");
		console.log(origins);
		const corsMiddleware = cors({
			origin: origins,
			credentials: true,
		});
		return corsMiddleware(c, next);
	});
}