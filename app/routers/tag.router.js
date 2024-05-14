import { Router } from 'express';
import * as tagController from '../controllers/tag.controller.js';
import cw from './controlerWrapper.router.js';

const router = Router();
export default router;

/**
 * Retrieves all tags.
 * @route GET /tags
 * @group Tags - Operations on tags
 * @returns {Array<Object>} List of tags.
 */
router.get('/tags', cw(tagController.getAllTags));

/**
 * Retrieves a specific tag by its ID.
 * @route GET /tags/{id}
 * @group Tags - Operations on tags
 * @param {string} req.params.id - The unique identifier of the tag to retrieve.
 * @returns {Object} The requested tag.
 */
router.get('/tags/:id', cw(tagController.getOneTag));

/**
 * Creates a new tag.
 * @route POST /tags
 * @group Tags - Operations on tags
 * @param {Object} req.body - Tag data to create.
 * @returns {Object} The created tag.
 */
router.post('/tags', cw(tagController.createTag));

/**
 * Updates an existing tag.
 * @route PATCH /tags/{id}
 * @group Tags - Operations on tags
 * @param {string} req.params.id - The unique identifier of the tag to update.
 * @param {Object} req.body - Updated tag data.
 * @returns {Object} The updated tag.
 */
router.patch('/tags/:id', cw(tagController.updateTag));

/**
 * Deletes an existing tag.
 * @route DELETE /tags/{id}
 * @group Tags - Operations on tags
 * @param {string} req.params.id - The unique identifier of the tag to delete.
 * @returns {string} Deletion confirmation message.
 */
router.delete('/tags/:id', cw(tagController.deleteTag));
