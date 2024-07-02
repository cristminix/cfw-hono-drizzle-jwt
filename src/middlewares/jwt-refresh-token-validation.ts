import { verify } from "hono/jwt";
import { getCookie } from "hono/cookie";
import { createHash } from "node:crypto";
import { bearerAuth } from "hono/bearer-auth";

export const validateRefreshToken = async (c,next) => {
	// Single valid privileged token
	const userFingerprintCookie = getCookie(
		c,
		c.env.JWT_FINGERPRINT_REFRESH_COOKIE_NAME,
	);
	if (!userFingerprintCookie)
		return c.json(
			{
				success: false,
				message: "empty fingerprint cookie",
			},
			401,
		);
	let userFingerprintDigest = createHash("sha256")
		.update(userFingerprintCookie, "utf-8")
		.digest("hex");

	console.log({ userFingerprintCookie, userFingerprintDigest });

	let message = "";

	const bearer = bearerAuth({
		verifyToken: async (token, c) => {
			// console.log(token)
			let verified = false;
			verified = await verify(token, c.env.SECRET);
			const { userFingerprint } = verified;
			console.log({ userFingerprint });
			if (!userFingerprint) {
				message = "Empty fingerprint token";
				return false;
			}
			if (userFingerprint !== userFingerprintDigest) {
				message = "Invalid fingerprint token";
				return false;
			}
			c.set('jwt',verified);
			return verified;
		},
	});
	let result;

	try {
		result = await bearer(c, next);
	} catch (e) {
		message = e.toString();
		if (message.match(/expired/)) message = "Token Expired";
		else message = "Unauthorized";
		// console.error(e);
	}

	console.log(result, message);
	if (result) return result;

	return c.json(
		{
			success: false,
			message,
		},
		401,
	);
};