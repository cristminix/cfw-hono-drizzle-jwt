import { InferModel, sql } from "drizzle-orm"
import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core"

export const sessions = sqliteTable("sessions", {
  // id is set on insert, incrementing
  id: integer("id", { mode: "number" }).primaryKey({ autoIncrement: true }),
  ipaddr: text("ipaddr", { length: 256 }).notNull(),
  uid: integer("uid", { mode: "number" }).notNull(),
  accessToken: text("accessToken", { length: 256 }).notNull(),
  kind: text("accessToken", { length: 50 }).notNull(),

  // timestamp is set on insert
  timestamp: text("timestamp")
    .default(sql`CURRENT_TIMESTAMP`)
    .notNull(),
})

export const users = sqliteTable("users", {
  // id is set on insert, incrementing
  id: integer("id", { mode: "number" }).primaryKey({ autoIncrement: true }),
  username: text("username", { length: 256 }).notNull(),
  email: text("email", { length: 256 }).notNull(),
  password: text("password", { length: 256 }).notNull(),

  // timestamp is set on insert
  timestamp: text("timestamp")
    .default(sql`CURRENT_TIMESTAMP`)
    .notNull(),
})

export const posts = sqliteTable("posts", {
  // id is set on insert, incrementing
  id: integer("id", { mode: "number" }).primaryKey({ autoIncrement: true }),

  // title of the blog post
  title: text("title", { length: 256 }).notNull(),

  // content of the blog post
  content: text("content", { length: 256 }).notNull(),

  // timestamp is set on insert
  timestamp: text("timestamp")
    .default(sql`CURRENT_TIMESTAMP`)
    .notNull(),
})

export type User = InferModel<typeof users>
export type Post = InferModel<typeof posts>
export type Session = InferModel<typeof sessions>
