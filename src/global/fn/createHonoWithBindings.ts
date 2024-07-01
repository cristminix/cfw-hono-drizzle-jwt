import { Hono } from "hono"
import {Env} from "../types/Env"

export const createHonoWithBindings = ()=>{
	return new Hono<{ Bindings: Env }>()
}