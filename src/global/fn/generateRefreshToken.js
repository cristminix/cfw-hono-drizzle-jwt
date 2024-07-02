
import {generateUserFingerprint} from "./generateUserFingerprint"
import { sign } from "hono/jwt"

export async function generateRefreshToken(secret,uid,exp){
  const ONE_MINUTES = Math.floor(Date.now() / 1000) + 60

  const {fingerprint,hash} = generateUserFingerprint()
	const payload = {
	    userFingerprint:hash,
	    uid,
	    exp: ONE_MINUTES * exp
	  }

	const token = await sign(payload, secret)

	return {
		token,fingerprint
	}
}