import { drizzle } from "drizzle-orm/d1"
import { and, eq } from "drizzle-orm"
import { sign } from "hono/jwt"
import { 
  setCookie 
} from "hono/cookie"
import { z } from "zod"
import { zBodyValidator } from "@hono-dev/zod-body-validator"
import { createHonoWithBindings } from '../global/fn/createHonoWithBindings';
import { encryptPassword } from '../global/fn/encryptPassword';
import { randomBytes, createHash } from "node:crypto"
import { users } from '../db/schema';

const registerValidationSchema = z.object({
  username: z.string(),
  password: z.string(),
  email: z.string().email(),
})

const loginValidationSchema = z.object({
  password: z.string(),
  email: z.string().email(),
})

const app = createHonoWithBindings()
app.post(
  "/register",
  zBodyValidator(registerValidationSchema),
  async (c) => {
    // const user = await c.req.json()
    const user = c.req.valid("form")
    console.log(user)
    const { username, email, password } = user

    const db = drizzle(c.env.DB)
    const isEmailAllReadyExist = await db
      .select()
      .from(users)
      .where(eq(users.email, email))

    if (isEmailAllReadyExist.length > 0) {
      return c.json({ success: false, message: "Email already in use" }, 400)
    }

    const newUser = {
      username,
      email,
      password: await encryptPassword(password, c.env.SECRET),
    }
    const result = await db.insert(users).values(newUser)
    return c.json(
      {
        success: result.success,
        message: result.success
          ? " User created Successfully"
          : "Create user failed",
        user: newUser,
      },
      201
    )
  }
)

app.post("/login", zBodyValidator(loginValidationSchema), async (c) => {
  ///////
  let keyHMAC
  // Random data generator
  let secureRandom = randomBytes(32).toString("hex")
  let randomFgp = new Uint32Array(50)
  crypto.getRandomValues(randomFgp)
  let userFingerprint = Array.from(randomFgp)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
  let fingerprintCookie =
    "__Secure-Fgp=" + userFingerprint + "; SameSite=None; HttpOnly; Secure"
  let userFingerprintDigest = createHash("sha256")
    .update(userFingerprint, "utf-8")
    .digest()

  let userFingerprintHash = userFingerprintDigest.toString("hex")
  console.log({
    secureRandom,
    userFingerprint,
    fingerprintCookie,
    userFingerprintHash,
  })

  ///////

  const user = c.req.valid("form")

  const { email, password } = user
  const db = drizzle(c.env.DB)
  let result = await db.select().from(users).where(eq(users.email, email))
  let isUserExist = result[0]

  if (!isUserExist) {
    return c.json({ success: false, message: "User not found" }, 404)
  }
  const encryptedPassword = await encryptPassword(password, c.env.SECRET)
  const isPasswordMatched = isUserExist?.password === encryptedPassword

  if (!isPasswordMatched) {
    return c.json({ success: false, message: "Wrong password" }, 404)
  }

  const payload = {
    userFingerprint: userFingerprintHash,
    email: isUserExist.email,
    exp: Math.floor(Date.now() / 1000) + 60 * 30, // Token expires in 5 minutes
  }
  const secret = c.env.SECRET
  const token = await sign(payload, secret)
  setCookie(c, "Secure-Fgp", userFingerprint, {
    // secure: true,
    httpOnly: true,
    sameSite: "Strict",
  })
  // setCookie(c, "delicious_cookie", "macha")

  return c.json({
    success: true,
    message: "login success",
    token: token,
  })
})

export default app