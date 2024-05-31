/* eslint-disable import/extensions */
/* eslint-disable max-len */
import { Card, Tag } from "../models/index.js";
import coreController from "./core.controller.js";

export default class cardController extends coreController {
  static tableName = Card;

  static stringTableName = "Card";

  static async create(req, res) {
    const { name, content, list_id } = req.body;
    try {
      const card = await Card.create({ name, content, list_id });
      const tag = await Tag.findOne({
        where: { name },
      });
      if (!tag) {
        tag = await Tag.create({ name, code_color });
      }
      await card.addTag(tag);
      return card;
    } catch (error) {
      console.error(error);
      res.status(500).json({
        error: "An error occurred while creating the card with tags.",
      });
    }
  }
}
