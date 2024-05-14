import pool from './client.js';
import coreDatamapper from './core.datamapper.js';

export default class projectDatamapper extends coreDatamapper {
  static tableName = 'project';

  static async findDetailsProject(id) {
    const result = await pool.query('SELECT * FROM project_details WHERE project_id = $1', [id]);
    return result.rows;
  }
}
