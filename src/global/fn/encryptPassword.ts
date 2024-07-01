export const encryptPassword = async (password: string, secret = "") => {
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