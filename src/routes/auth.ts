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
import {generateAccessToken} from '../global/fn/generateAccessToken'
import {generateRefreshToken} from '../global/fn/generateRefreshToken'
// import { randomBytes, createHash } from "node:crypto"
import { users } from '../db/schema';
import {validateRefreshToken} from "../middlewares/jwt-refresh-token-validation"

const registerValidationSchema = z.object({
  username: z.string(),
  password: z.string(),
  email: z.string().email(),
})

const loginValidationSchema = z.object({
  password: z.string(),
  email: z.string().email(),
})

// const refreshTokenValidationSchema = z.object({
//   refreshToken: z.string(),
// })

const app = createHonoWithBindings()
  
app.post("/refresh",async(c,next)=>await validateRefreshToken(c,next),async(c)=>{
  // const result = await 
  const {uid} = c.get('jwt')
   const token = await generateAccessToken(c.env.SECRET,uid, c.env.TOKEN_EXPIRATION)
  setCookie(c, c.env.JWT_FINGERPRINT_COOKIE_NAME, token.fingerprint, {
    secure: true,
    httpOnly: true,
    sameSite: "Strict",
  })
  return c.json({
    token: token.token
  })
})

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

  const user = c.req.valid("form")

  const { email, password } = user
  const db = drizzle(c.env.DB)
  let result = await db.select().from(users).where(eq(users.email, email))
  let userRow = result[0]

  if (!userRow) {
    return c.json({ success: false, message: "User not found" }, 404)
  }
  const encryptedPassword = await encryptPassword(password, c.env.SECRET)
  const isPasswordMatched = userRow?.password === encryptedPassword

  if (!isPasswordMatched) {
    return c.json({ success: false, message: "Wrong password" }, 404)
  }
  const token = await generateAccessToken(c.env.SECRET,userRow.id, c.env.TOKEN_EXPIRATION)

  const refreshToken = await generateRefreshToken(c.env.SECRET,userRow.id, c.env.REFRESH_TOKEN_EXPIRATION)  
  
  setCookie(c, c.env.JWT_FINGERPRINT_COOKIE_NAME, token.fingerprint, {
    secure: true,
    httpOnly: true,
    sameSite: "Strict",
  })
  setCookie(c, c.env.JWT_FINGERPRINT_REFRESH_COOKIE_NAME, refreshToken.fingerprint, {
    secure: true,
    httpOnly: true,
    sameSite: "Strict",
  })


  return c.json({
    success: true,
    message: "login success",
    token: token.token,
    refreshToken: refreshToken.token,
  })
})

export default app