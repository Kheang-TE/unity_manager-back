import { Router } from 'express';
import * as userController from '../controllers/user.controller.js';
import cw from './controlerWrapper.router.js';

const router = Router();
export default router;

/**
 * Retrieve all users.
 * @route GET /users
 * @group Users - Operations on users
 * @returns {Array<Object>} List of users.
 */
router.get('/users', cw(userController.getAllUsers));
/**
 * Retrieve a specific user by its ID.
 * @route GET /users/{id}
 * @group Users - Operations on users
 * @param {string} req.params.id - The unique identifier of the user to retrieve.
 * @returns {Object} The requested user.
 */
router.get('/users/:id', cw(userController.getOneUser));

/**
 * Create a new user.
 * @route POST /users
 * @group Users - Operations on users
 * @param {Object} req.body - User data to create.
 * @returns {Object} The created user.
 */
router.post('/users', cw(userController.createUser));

/**
 * Update an existing user.
 * @route PATCH /users/{id}
 * @group Users - Operations on users
 * @param {string} req.params.id - The unique identifier of the user to update.
 * @param {Object} req.body - Updated user data.
 * @returns {Object} The updated user.
 */
router.patch('/users/:id', cw(userController.updateUser));

/**
 * Delete an existing user.
 * @route DELETE /users/{id}
 * @group Users - Operations on users
 * @param {string} req.params.id - The unique identifier of the user to delete.
 * @returns {string} Deletion confirmation message.
 */
router.delete('/users/:id', cw(userController.deleteUser));
