import {sessions} from "../../db/schema"
import DrizzleModel from "./DrizzleModel"
class MSession extends DrizzleModel{
	schema=sessions
}
export default MSession