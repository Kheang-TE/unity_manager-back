import ApiError from '../errors/api.error.js';

export default class coreController {
  static tableName = null;

  static stringTableName = null;

  /**
   * Retrieves all data from the database and sends it as a JSON response.
   *
   * @param {Object} req - The request object
   * @param {Object} res - The response object
   * @return {Object} The JSON response containing all retrieved data
   */
  static async getAll(req, res) {
    const results = await this.tableName.findAll();
    res.json(results);
  }

  /**
   * Retrieves all data from the database and sends it as a JSON response.
   *
   * @param {Object} req - The request object
   * @param {Object} res - The response object
   * @return {Object} The JSON response containing all retrieved data
   */
  static async getOne(req, res) {
    const id = +req.params.id;
    if (!Number.isInteger(id)) {
      throw new ApiError(400, 'Bad Request', 'The provided ID is not a number');
    }

    const result = await this.tableName.findByPk(id);

    if (!result) {
      throw new ApiError(404, 'Data not found', `${this.stringTableName} not found with the provided the ID: ${id}`);
    }
    return res.json(result);
  }

  /**
   * Deletes a specific record from the database based on the provided ID.
   *
   * @param {Object} req - The request object
   * @param {Object} res - The response object
   * @return {Object} No content response
   */
  static async deleteOne(req, res) {
    const id = +req.params.id;
    if (!Number.isInteger(id)) {
      throw new ApiError(400, 'Bad Request', 'The provided ID is not a number');
    }
    const result = await this.tableName.findByPk(id);
    if (!result) {
      throw new ApiError(404, 'Data not found', `${this.stringTableName} not found with the provided the ID: ${id}`);
    }
    await result.destroy();
    return res.status(204).end();
  }

  /**
   * Creates a new record in the database based on the input data.
   *
   * @param {Object} req - The request object containing the data to create the record.
   * @param {Object} res - The response object to send the result.
   * @return {Object} The created record as a JSON response with status code 201.
   */
  static async create(req, res) {
    const input = req.body;
    const result = await this.tableName.create(input);
    return res.status(201).json(result);
  }

  /**
   * A function to update a specific record in the database.
   *
   * @param {Object} req - The request object containing the ID and updated data
   * @param {Object} res - The response object to send the updated record
   * @return {Object} The updated record as a JSON response
   */
  static async update(req, res) {
    const id = +req.params.id;
    if (!Number.isInteger(id)) {
      throw new ApiError(400, 'Bad Request', 'The provided ID is not a number');
    }
    const input = req.body;
    const result = await this.tableName.findByPk(id);
    if (!result) {
      throw new ApiError(404, 'Data not found', `${this.stringTableName} not found with the provided the ID: ${id}`);
    }
    await result.update(input);
    return res.json(result);
  }
}
