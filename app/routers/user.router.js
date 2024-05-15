import { Router } from 'express';
import userController from '../controllers/user.controller.js';
import wrapper from '../middlewares/controller.wrapper.js';

const router = Router();
export default router;

/**
 * Retrieve all users.
 * @route GET /users
 * @group Users - Operations on users
 * @returns {Array<Object>} List of users.
 */
router.get('/users', wrapper(userController.getAll.bind(userController)));
/**
 * Retrieve a specific user by its ID.
 * @route GET /users/{id}
 * @group Users - Operations on users
 * @param {string} req.params.id - The unique identifier of the user to retrieve.
 * @returns {Object} The requested user.
 */
router.get('/users/:id', wrapper(userController.getOne.bind(userController)));

/**
 * Create a new user.
 * @route POST /users
 * @group Users - Operations on users
 * @param {Object} req.body - User data to create.
 * @returns {Object} The created user.
 */
router.post('/users', wrapper(userController.createUser.bind(userController)));

/**
 * Update an existing user.
 * @route PATCH /users/{id}
 * @group Users - Operations on users
 * @param {string} req.params.id - The unique identifier of the user to update.
 * @param {Object} req.body - Updated user data.
 * @returns {Object} The updated user.
 */

/*
router.patch(
  '/users/:id',
  wrapper(userController.updateUser.bind(userController)),
);*/

/**
 * Delete an existing user.
 * @route DELETE /users/{id}
 * @group Users - Operations on users
 * @param {string} req.params.id - The unique identifier of the user to delete.
 * @returns {string} Deletion confirmation message.
 */
router.delete(
  '/users/:id',
  wrapper(userController.deleteOne.bind(userController)),
);
