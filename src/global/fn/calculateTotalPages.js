export const calculateTotalPages = (recordCount, limit) => {
  return Math.ceil(recordCount / limit)
}