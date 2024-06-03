import { Router } from 'express';
import cardController from '../controllers/card.controller.js';
import wrapper from '../middlewares/controller.wrapper.js';
import createSchema from '../schemas/card.create.schema.js';
import updateSchema from '../schemas/card.update.schema.js';
import validationMiddleware from '../middlewares/validation.middleware.js';

const router = Router();

router
  .route('/')
  /**
   * Retrieves all cards.
   * @route GET /cards
   * @group Cards - Operations on cards
   * @returns {Array<Object>} List of cards.
   */
  .get(wrapper(cardController.getAll.bind(cardController)))

  /**
   * Creates a new card.
   * @route POST /cards
   * @group Cards - Operations on cards
   * @param {Object} req.body - Card data to create.
   * @returns {Object} The created card.
   */
  .post(validationMiddleware(createSchema, 'body'), wrapper(cardController.create.bind(cardController)));

router.route('/:id')
  /**
   * Retrieves a specific card by its ID.
   * @route GET /cards/{id}
   * @group Cards - Operations on cards
   * @param {string} req.params.id - The unique identifier of the card to retrieve.
   * @returns {Object} The requested card.
   */
  .get(wrapper(cardController.getOne.bind(cardController)))
  /**
   * Updates an existing card.
   * @route PATCH /cards/{id}
   * @group Cards - Operations on cards
   * @param {string} req.params.id - The unique identifier of the card to update.
   * @param {Object} req.body - Updated card data.
   * @returns {Object} The updated card.
   */
  .patch(validationMiddleware(updateSchema, 'body'), wrapper(cardController.update.bind(cardController)))

  /**
   * Deletes an existing card.
   * @route DELETE /cards/{id}
   * @group Cards - Operations on cards
   * @param {string} req.params.id - The unique identifier of the card to delete.
   * @returns {string} Deletion confirmation message.
   */
  .delete(wrapper(cardController.deleteOne.bind(cardController)));

export default router;
