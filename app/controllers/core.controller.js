import Joi from 'joi';

export default class coreController {
  static tableName = null;

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
    const { error } = Joi.number().integer().greater(0).validate(req.params.id);
    if (error) {
      return res.status(400).json({
        error: `Card not found. Verify the provided ID. ${error.message}`,
      });
    }
    const id = +req.params.id;
    const result = await this.tableName.findByPk(id);
    if (!result) {
      return res.status(404).json({
        error: 'Data not found',
      });
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
    const result = await this.tableName.findByPk(id);
    if (!result) {
      return res.status(404).json({ error: 'Data not found' });
    }
    await result.destroy();
    return res.status(204).end();
  }
}
