export const calculateOffset = (pageNumber, limit) => {
  const offset = (pageNumber - 1) * limit
  return offset
}