import { Router } from 'express';
// import * as messageController from '../controllers/message.controller.js';
import controllerWrapper from '../middlewares/controller.wrapper.js';
import messageController from '../controllers/message.controller.js';
import createSchema from '../schemas/message.create.schema.js';
import updateSchema from '../schemas/message.update.schema.js';
import validationMiddleware from '../middlewares/validation.middleware.js';
import setUserId from '../middlewares/userIdFromTokenToBody.middleware.js';

const router = Router();
export default router;
router.route('/projects/:id').get(controllerWrapper(messageController.getByProjectId));
router
  .route('/')
  /**
   * Retrieves all messages.
   * @route GET /messages
   * @group Messages - Operations on messages
   * @returns {Array<Object>} List of messages.
   */
  .get(controllerWrapper(messageController.getAll))

  .post(setUserId, validationMiddleware(createSchema, 'body'), controllerWrapper(messageController.create));

router.route('/:id')
  /**
   * Retrieves a specific message by its ID.
   * @route GET /messages/{id}
   * @group Messages - Operations on messages
   * @param {string} req.params.id - The unique identifier of the message to retrieve.
   * @returns {Object} The requested message.
   */
  .get(controllerWrapper(messageController.getOne))

  .patch(validationMiddleware(updateSchema, 'body'), controllerWrapper(messageController.update))

  .delete(controllerWrapper(messageController.deleteOne));
