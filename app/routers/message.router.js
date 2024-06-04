import { Router } from 'express';

import controllerWrapper from '../middlewares/controller.wrapper.js';
import messageController from '../controllers/message.controller.js';
import createSchema from '../schemas/message.create.schema.js';
import updateSchema from '../schemas/message.update.schema.js';
import validationMiddleware from '../middlewares/validation.middleware.js';

const router = Router();
export default router;
router.route('/projects/:id')
  /**
   * Retrieves all messages by project ID.
   * @route GET /messages/projects/{id}
   * @group Messages - Operations on messages
   * @param {string} req.params.id - The unique identifier of the project to retrieve messages from.
   * @returns {Array<Object>} List of messages.
   */
  .get(controllerWrapper(messageController.getByProjectId));
router
  .route('/')
  /**
   * Retrieves all messages.
   * @route GET /messages
   * @group Messages - Operations on messages
   * @returns {Array<Object>} List of messages.
   */
  .get(controllerWrapper(messageController.getAll))
  /**
   * Creates a new message.
   * @route POST /messages
   * @group Messages - Operations on messages
   * @param {Object} req.body - Message data to create.
   * @returns {Object} The created message.
   */
  .post(validationMiddleware(createSchema, 'body'), controllerWrapper(messageController.create));

router.route('/:id')
  /**
   * Retrieves a specific message by its ID.
   * @route GET /messages/{id}
   * @group Messages - Operations on messages
   * @param {string} req.params.id - The unique identifier of the message to retrieve.
   * @returns {Object} The requested message.
   */
  .get(controllerWrapper(messageController.getOne))
  /**
   * Updates an existing message.
   * @route PATCH /messages/{id}
   * @group Messages - Operations on messages
   * @param {string} req.params.id - The unique identifier of the message to update.
   * @param {Object} req.body - Updated message data.
   * @returns {Object} The updated message.
   */
  .patch(validationMiddleware(updateSchema, 'body'), controllerWrapper(messageController.update))

  /**
   * Deletes an existing message.
   * @route DELETE /messages/{id}
   * @group Messages - Operations on messages
   * @param {string} req.params.id - The unique identifier of the message to delete.
   * @returns {string} Deletion confirmation message.
   */
  .delete(controllerWrapper(messageController.deleteOne));
