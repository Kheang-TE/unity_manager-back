/* eslint-disable import/extensions */
/* eslint-disable max-len */
import { Card, Tag } from '../models/index.js';
import coreController from './core.controller.js';
import ApiError from '../errors/api.error.js';

export default class cardController extends coreController {
  static tableName = Card;

  static stringTableName = 'Card';

  static async create(req, res) {
    const {
      name,
      content,
      list_id,
      position,
      tags,
    } = req.body;

    const card = await Card.create({
      name, content, list_id, position,
    });
    if (tags && tags.length > 0) {
      tags.forEach(async (tagId) => {
        const tag = await Tag.findByPk(tagId);
        if (!tag) {
          res.status(404).json({
            error: `Tag not found with the provided the ID: ${tagId}`,
          });
        }
        await card.addTag(tag);
      });
    }
    return res.status(201).json({ message: 'Card was successfully created' });
  }

  static async getOne(req, res, next) {
    const id = +req.params.id;
    if (!Number.isInteger(id)) {
      next(new ApiError(400, 'Bad Request', 'The provided ID is not a number'));
    }

    const card = await this.tableName.findByPk(id, {
      include: [{
        model: Tag,
        as: 'tags',
        through: { attributes: [] },
      }],
    });

    if (!card) {
      return next(new ApiError(404, 'Data not found', `${this.stringTableName} not found with the provided the ID: ${id}`));
    }
    return res.json(card);
  }

  static async update(req, res, next) {
    const id = +req.params.id;
    if (!Number.isInteger(id)) {
      return next(new ApiError(400, 'Bad Request', 'The provided ID is not a number'));
    }
    const {
      name, content, list_id, position,
    } = req.body;
    const card = await this.tableName.findByPk(id);
    if (!card) {
      return next(new ApiError(404, 'Data not found', `${this.stringTableName} not found with the provided the ID: ${id}`));
    }
    await card.update({
      name, content, list_id, position,
    });
    if (req.body.tags && req.body.tags.length > 0) {
      const { tags } = req.body;
      tags.forEach(async (tagId) => {
        const tag = await Tag.findByPk(tagId);
        if (!tag) {
          next(new ApiError(404, 'Data not found', `Tag not found with the provided the ID: ${tagId}`));
        }
        await card.addTag(tag);
      });
    }

    return res.status(201).json({ message: 'Card was successfully updated' });
  }
}
