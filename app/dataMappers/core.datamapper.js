import pool from './client';

export default class coreDatamapper {
  constructor(tableName) {
    this.tableName = tableName;
  }

  static async findAll() {
    const result = await pool.query(`SELECT * FROM ${this.tableName}`);
    return result.rows;
  }

  static async findOne(id) {
    const result = await pool.query(`SELECT * FROM ${this.tableName} WHERE id LIKE $1`, [id]);
    return result.rows[0];
  }

  static async deleteOne(id) {
    const result = await pool.query(`DELETE * FROM ${this.tableName} WHERE id LIKE $1`, [id]);
    return result.rows[0];
  }
}
