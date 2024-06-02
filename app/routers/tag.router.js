import { Router } from 'express';
import tagController from '../controllers/tag.controller.js';
import wrapper from '../middlewares/controller.wrapper.js';
import createSchema from '../schemas/tag.create.schema.js';
import updateSchema from '../schemas/tag.update.schema.js';
import validationMiddleware from '../middlewares/validation.middleware.js';

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
   * Creates a new tag.
   * @route POST /tags
   * @group Tags - Operations on tags
   * @param {Object} req.body - Tag data to create.
   * @returns {Object} The created tag.
   */
  .post(validationMiddleware(createSchema, 'body'), wrapper(tagController.create.bind(tagController)));

router.route('/:id')

  /**
   * Retrieves a specific tag by its ID.
   * @route GET /tags/{id}
   * @group Tags - Operations on tags
   * @param {string} req.params.id - The unique identifier of the tag to retrieve.
   * @returns {Object} The requested tag.
   */
  .get(wrapper(tagController.getOne.bind(tagController)))

  /**
   * Updates an existing tag.
   * @route PATCH /tags/{id}
   * @group Tags - Operations on tags
   * @param {string} req.params.id - The unique identifier of the tag to update.
   * @param {Object} req.body - Updated tag data.
   * @returns {Object} The updated tag.
   */
  .patch(validationMiddleware(updateSchema, 'body'), wrapper(tagController.update.bind(tagController)))

  /**
   * Deletes an existing tag.
   * @route DELETE /tags/{id}
   * @group Tags - Operations on tags
   * @param {string} req.params.id - The unique identifier of the tag to delete.
   * @returns {string} Deletion confirmation message.
   */
  .delete(wrapper(tagController.deleteOne.bind(tagController)));

router.route('/projects/:id').get(wrapper(tagController.getByProject.bind(tagController)));

export default router;
