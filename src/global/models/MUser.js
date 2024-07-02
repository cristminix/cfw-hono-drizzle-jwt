import {users} from "../../db/schema"
import DrizzleModel from "./DrizzleModel"
class MUser extends DrizzleModel{
	schema=users
}
export default MUser