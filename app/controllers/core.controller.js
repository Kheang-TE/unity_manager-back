import Joi from 'joi';

export default class coreController {
  constructor(tableName) {
    this.tableName = tableName;
  }

  static async getAll(req, res) {
    const result = await this.tableName.findAll();
    res.json(result);
  }

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

  static async deleteOne(req, res) {
    const id = +req.params.id;
    const result = await this.Project.findByPk(id);
    if (!result) {
      return res.status(404).json({ error: 'Data not found' });
    }
    await result.destroy();
    return res.status(204).end();
  }
}
