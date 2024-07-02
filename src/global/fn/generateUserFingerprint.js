import { createHash } from "node:crypto"

export function generateUserFingerprint(){
	
  let randomFgp = new Uint32Array(50)
  crypto.getRandomValues(randomFgp)
  let userFingerprint = Array.from(randomFgp)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
  let userFingerprintDigest = createHash("sha256")
    .update(userFingerprint, "utf-8")
    .digest()

  let userFingerprintHash = userFingerprintDigest.toString("hex")
	return {
		fingerprint:userFingerprint,
		hash:userFingerprintHash
	}
}