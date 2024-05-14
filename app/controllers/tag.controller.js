// eslint-disable-next-line import/no-unresolved, import/extensions
import Joi from 'joi';
import { Tag } from '../models';

/**
 * Retrieves all tags from the database and returns them.
 *
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 * @return {Object} The list of tags or an error message
 */
export async function getAllTags(req, res) {
  const tags = await Tag.findAll();
  if (!tags) {
    return res.status(404).json({
      error: 'The requested resource could not be found on the server.',
    });
  }
  return res.status(200).json(tags);
}

/**
 * Retrieves a single tag based on the provided ID.
 *
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 * @return {Object} The tag object or an error message
 */
export async function getOneTag(req, res) {
  const tagId = +req.params.id;
  if (!Number.isInteger(tagId)) {
    return res.status(404).json({
      error: 'The requested resource could not be found on the server.',
    });
  }
  const tag = await Tag.findByPk(+tagId);
  if (!tag) {
    return res.status(404).json({ error: 'Tag not found.' });
  }
  return res.status(200).json(tag);
}

/**
 * Create a new tag based on the provided name.
 *
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 * @return {Object} The newly created tag or an error message
 */
export async function createTag(req, res) {
  const { name } = req.body;
  if (!name || typeof name !== 'string') {
    return res.status(400).json({
      error: "Missing body parameter or invalid format: 'name'.",
    });
  }
  const createTagVerificationError = Joi.object({
    name: Joi.string().min(1),
  })
    .min(1)
    .message('The name field is not valid.');

  const { error } = createTagVerificationError.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.message });
  }
  const newTag = await Tag.create({ name });
  return res.status(200).json(newTag);
}

/**
 * Updates a tag based on the provided request body.
 *
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 * @return {Object} The updated tag object or an error message
 */
export async function updateTag(req, res) {
  const { body } = req;
  if (!body.name || !body.code_color) {
    return res.status(404).json({
      error: 'The requested resource could not be found on the server.',
    });
  }
  const tagId = +req.params.id;
  if (!Number.isInteger(tagId)) {
    return res.status(404).json({ error: 'The ID of tag is not defined. ' });
  }
  const updateTagSchema = Joi.object({
    name: Joi.string().min(1),
  })
    .min(1)
    .message("At least property 'name' or' should be provided.");

  const { error } = updateTagSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.message });
  }
  const updateOneTag = await Tag.findByPk(+tagId);
  await updateOneTag.update(body);
  await updateOneTag.save();
  return res.status(200).json(updateOneTag);
}

/**
 * Deletes a tag from the server based on the provided tag ID.
 *
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 * @return {Object} The result of the deletion operation
 */
export async function deleteTag(req, res) {
  const tagId = +req.params.id;
  if (!Number.isInteger(tagId)) {
    return res.status(404).json({ error: 'The ID of tag is not defined. ' });
  }
  const findTagByPk = await Tag.findByPk(tagId);
  if (!findTagByPk) {
    res.status(404).json({ error: "The 'Tag' is not defined on the server." });
  }
  await Tag.destroy();
  return res.status(204).end(findTagByPk);
}

/**
 * Retrieves a tag associated with a card based on the provided card and tag IDs.
 *
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 * @return {Object} The found tag object or an error message
 */
export async function associationTagWithCard(req, res) {
  const cardId = +req.params.card_id;
  const tagId = +req.params.tag_id;
  try {
    const findTag = await Tag.findOne({ card_id: cardId, tag_id: tagId });
    if (!findTag) {
      return res.status(404).json({
        error: 'The requested resource could not be found on the server.',
      });
    }
    return res.json(findTag);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Unexpected server error' });
  }
}

/**
 * Deletes a tag associated with a card based on the provided card and tag IDs.
 *
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 * @return {Object} The deleted tag object or an error message
 */
export async function deleteAssociatTagCard(req, res) {
  try {
    const cardId = +req.params.card_id;
    const tagId = +req.params.tag_id;

    const findTag = await Tag.findOneAndDelete({ card_id: cardId, tag_id: tagId });

    if (!findTag) {
      return res.status(404).json({ error: 'The association between the card and tag could not be found.' });
    }

    return res.json({ message: 'Association between card and tag was successfully deleted.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'An unexpected server error occurred' });
  }
}
