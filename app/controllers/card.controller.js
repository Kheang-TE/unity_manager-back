/* eslint-disable import/extensions */
/* eslint-disable max-len */
import { Card, Tag } from '../models/index.js';
import coreController from './core.controller.js';

export default class cardController extends coreController {
  static tableName = Card;

  static stringTableName = 'Card';

  // static async create(req, res) {
  //   const { name, content, list_id } = req.body;
  //   try {
  //     const card = await Card.create({ name, content, list_id });
  //     const tag = await Tag.findOne({
  //       where: { name },
  //     });
  //     if (!tag) {
  //       tag = await Tag.create({ name, code_color });
  //     }
  //     await card.addTag(tag);
  //     return card;
  //   } catch (error) {
  //     console.error(error);
  //     res.status(500).json({
  //       error: "An error occurred while creating the card with tags.",
  //     });
  //   }
  // }

  static async getCardWithTags(req, res) {
    const cardId = +req.params.id;
    try {
      const card = await Card.findByPk(cardId, {
        include: [{
          model: Tag,
          as: 'tags',
          through: { attributes: [] },
        }],
      });
      return res.send(card);
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: 'Unexpected server error' });
    }
  }

  static async addTagsToCard(req, res) {
    const cardId = +req.params.id;
    const { tags } = req.body;
    const tagsArray = [];

    const card = await Card.findByPk(cardId);
    if (!card) {
      return res.status(404).json({
        error: 'The requested resource could not be found on the server.',
      });
    }

    tags.forEach(async (tagInput) => {
      const tag = await Tag.findByPk(tagInput.id);
      if (!tag) {
        return res.status(404).json({
          error: 'The requested resource could not be found on the server.',
        });
      }
      tagsArray.push(tag);
    });

    tagsArray.forEach(async (tag) => {
      const cardTag = await card.addTag(tag);
      if (!cardTag) {
        return res.status(404).json({
          error: 'The requested resource could not be found on the server.',
        });
      }
      return res.status(200).json({ message: 'Tags added to card successfully' });
    });
  }

  static async updateTagsInCard(req, res) {
    const cardId = +req.params.id;
    const { tags } = req.body;
    const tagsArray = [];

    const card = await Card.findByPk(cardId, {
      include: [{
        model: Tag,
        as: 'tags',
        through: { attributes: [] },
      }],
    });
    if (!card) {
      return res.status(404).json({
        error: 'The requested resource could not be found on the server.',
      });
    }

    card.tags.forEach(async (tag) => {
      const cardTag = await card.removeTag(tag);
      if (!cardTag) {
        return res.status(404).json({
          error: 'The requested resource could not be found on the server.',
        });
      }
    });

    tags.forEach(async (tagInput) => {
      const tag = await Tag.findByPk(tagInput.id);
      if (!tag) {
        return res.status(404).json({
          error: 'The requested resource could not be found on the server.',
        });
      }
      return tagsArray.push(tag);
    });
  }

  static async removeTagsFromCard(req, res) {
    const cardId = +req.params.id;
    const { tags } = req.body;
    const tagsArray = [];

    const card = await Card.findByPk(cardId, {
      include: [{
        model: Tag,
        as: 'tags',
        through: { attributes: [] },
      }],
    });
    if (!card) {
      return res.status(404).json({
        error: 'The requested resource could not be found on the server.',
      });
    }

    tags.forEach(async (tagInput) => {
      const tag = await Tag.findByPk(tagInput.id);
      if (!tag) {
        return res.status(404).json({
          error: 'The requested resource could not be found on the server.',
        });
      }
      return tagsArray.push(tag);
    });

    tagsArray.forEach(async (tag) => {
      const cardTag = await card.removeTag(tag);
      if (!cardTag) {
        return res.status(404).json({
          error: 'The requested resource could not be found on the server.',
        });
      }
      return res.status(200).json({ message: 'Tags removed from card successfully' });
    });
  }
}
