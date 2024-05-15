import { Router } from 'express';
import tagController from '../controllers/tag.controller.js';
import wrapper from '../middlewares/controller.wrapper.js';

const router = Router();
router
  .route('/')
  /**
   * Retrieves all tags.
   * @route GET /tags
   * @group Tags - Operations on tags
   * @returns {Array<Object>} List of tags.
   */
  .get(wrapper(tagController.getAll.bind(tagController)))

  /**
   * Retrieves a specific tag by its ID.
   * @route GET /tags/{id}
   * @group Tags - Operations on tags
   * @param {string} req.params.id - The unique identifier of the tag to retrieve.
   * @returns {Object} The requested tag.
   */
  .get('/:id', wrapper(tagController.getOne.bind(tagController)))

  /**
   * Creates a new tag.
   * @route POST /tags
   * @group Tags - Operations on tags
   * @param {Object} req.body - Tag data to create.
   * @returns {Object} The created tag.
   */
  .post(wrapper(tagController.createTag.bind(tagController)))

  /**
   * Updates an existing tag.
   * @route PATCH /tags/{id}
   * @group Tags - Operations on tags
   * @param {string} req.params.id - The unique identifier of the tag to update.
   * @param {Object} req.body - Updated tag data.
   * @returns {Object} The updated tag.
   */
  .patch('/:id', wrapper(tagController.updateTag.bind(tagController)))

  /**
   * Deletes an existing tag.
   * @route DELETE /tags/{id}
   * @group Tags - Operations on tags
   * @param {string} req.params.id - The unique identifier of the tag to delete.
   * @returns {string} Deletion confirmation message.
   */
  .delete('/:id', wrapper(tagController.deleteOne.bind(tagController)));

export default router;

