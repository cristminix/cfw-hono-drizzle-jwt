import { Hono } from "hono"
import { decode, sign, verify } from "hono/jwt"
import { drizzle } from "drizzle-orm/d1"
import { posts, users } from "./db/schema"
import { HTTPException } from "hono/http-exception"
import { cors } from "hono/cors"

import { and, eq } from "drizzle-orm"
import { z } from "zod"
import { zBodyValidator } from "@hono-dev/zod-body-validator"
import { bearerAuth } from "hono/bearer-auth"
import { randomBytes, createHash } from "node:crypto"
import {
  getCookie,
  getSignedCookie,
  setCookie,
  setSignedCookie,
  deleteCookie,
} from "hono/cookie"
const registerValidationSchema = z.object({
  username: z.string(),
  password: z.string(),
  email: z.string().email(),
})
const loginValidationSchema = z.object({
  password: z.string(),
  email: z.string().email(),
})

export type Env = {
  DB: D1Database
  MY_VAR: string
  PRIVATE: string
  SECRET: string
  ALLOWED_ORIGINS: any
}

const encryptPassword = async (password: string, secret = "") => {
  //encrypt password
  const clearPasswordBuffer = new TextEncoder().encode(`${password}-${secret}`)

  const passwordDigest = await crypto.subtle.digest(
    {
      name: "MD5",
    },
    clearPasswordBuffer // The data you want to hash as an ArrayBuffer
  )
  const passwordHash = [...new Uint8Array(passwordDigest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")

  return passwordHash
}
const app = new Hono<{ Bindings: Env }>()

app.use("*", (c, next) => {
  const origins =
    c.env.ALLOWED_ORIGINS == "*" ? "*" : c.env.ALLOWED_ORIGINS.split(",")
  console.log(origins)
  const corsMiddleware = cors({
    origin: origins,
    credentials: true,
  })
  return corsMiddleware(c, next)
})
app.use("/api/*", async (c, next) => {
  // Single valid privileged token
  const userFingerprintCookie = getCookie(c, "Secure-Fgp")
  let userFingerprintDigest = createHash("sha256")
    .update(userFingerprintCookie, "utf-8")
    .digest("hex")
  console.log({ userFingerprintCookie, userFingerprintDigest })

  let message = ""
  const bearer = bearerAuth({
    verifyToken: async (token, c) => {
      let verified = false
      verified = await verify(token, c.env.SECRET)
      const { userFingerprint } = verified
      if (!userFingerprint) {
        message = "Empty fingerprint token"
        return false
      }
      if (userFingerprint !== userFingerprintDigest) {
        message = "Invalid fingerprint token"
        return false
      }
      console.log(verified)
      return verified
    },
  })
  let result
  try {
    result = await bearer(c, next)
  } catch (e) {
    message = e.toString()
    if (message.match(/expired/)) message = "Token Expired"
    else message = "Unauthorized"
    // console.error(e);
  }
  console.log(result, message)
  if (result) return result
  return c.json(
    {
      success: false,
      message,
    },
    401
  )
})

app.get("/", (c) => {
  return c.html("<h1>Welcome To JWT Authentication </h1>")
})

app.post(
  "/auth/register",
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

app.post("/auth/login", zBodyValidator(loginValidationSchema), async (c) => {
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
  setCookie(c, "delicious_cookie", "macha")

  return c.json({
    success: true,
    message: "login success",
    token: token,
  })
})
app.get("/api/posts", async (c) => {
  const db = drizzle(c.env.DB)
  const result = await db.select().from(posts).all()
  return c.json({
    success: true,
    posts: result,
  })
})
app.get("/api/users", async (c) => {
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
