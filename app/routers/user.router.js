import { Router } from 'express';
import userController from '../controllers/user.controller.js';
import wrapper from '../middlewares/controller.wrapper.js';
import createSchema from '../schemas/user.create.schema.js';
import updateSchema from '../schemas/user.update.schema.js';
import signinSchema from '../schemas/user.signin.schema.js';
import validationMiddleware from '../middlewares/validation.middleware.js';
// import authMiddleware from '../middlewares/authentification.middleware.js';

const router = Router();
router
  .route('/')
  /**
   * Retrieve all users.
   * @route GET /users
   * @group Users - Operations on users
   * @returns {Array<Object>} List of users.
   */
  .get(wrapper(userController.getAll.bind(userController)))

  /**
   * Create a new user.
   * @route POST /users
   * @group Users - Operations on users
   * @param {Object} req.body - User data to create.
   * @returns {Object} The created user.
   */
  .post(validationMiddleware(createSchema, 'body'), wrapper(userController.createUser.bind(userController)));

router.route('/signin')
  .post(validationMiddleware(signinSchema, 'body'), wrapper(userController.signIn.bind(userController)));

router.route('/board')
  .get(wrapper(userController.getUserBoard.bind(userController)));

router.route('/:id')

  /**
   * Retrieve a specific user by its ID.
   * @route GET /users/{id}
   * @group Users - Operations on users
   * @param {string} req.params.id - The unique identifier of the user to retrieve.
   * @returns {Object} The requested user.
   */
  .get(wrapper(userController.getOne.bind(userController)))
  /**
   * Update an existing user.
   * @route PATCH /users/{id}
   * @group Users - Operations on users
   * @param {string} req.params.id - The unique identifier of the user to update.
   * @param {Object} req.body - Updated user data.
   * @returns {Object} The updated user.
   */
  .patch(validationMiddleware(updateSchema, 'body'), wrapper(userController.updateUser.bind(userController)))

  /**
   * Delete an existing user.
   * @route DELETE /users/{id}
   * @group Users - Operations on users
   * @param {string} req.params.id - The unique identifier of the user to delete.
   * @returns {string} Deletion confirmation message.
   */
  .delete(wrapper(userController.deleteOne.bind(userController)));

export default router;
