
import { count, sql, eq, and, asc, desc, like, or } from "drizzle-orm"
import DrizzleBaseModel from "./DrizzleBaseModel"
import { calculateTotalPages } from '../fn/calculateTotalPages';
import { calculateOffset } from '../fn/calculateOffset';

class DrizzleModel extends DrizzleBaseModel {

	
	async update(pk, row_) {
		const row = {...row_}
		delete row[this.pk]
		return await this.db.update(this.schema).set(row).where(eq(this.schema[this.pk], pk))
	}
	async updateByFieldFilter(field,value, row_) {
		const row = {...row_}

		delete row[this.pk]
		return await this.db.update(this.schema).set(row).where(eq(this.schema[field], value))
	}
	async delete(pk, row) {
		return await this.db.delete(this.schema).where(eq(this.schema[this.pk], pk))
	}
	async create( row) {
		return await await this.db.insert(this.schema).values(row)
	}
}

export default DrizzleModel