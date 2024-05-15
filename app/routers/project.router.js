import { Router } from 'express';
import projectController from '../controllers/user.controller.js';
import wrapper from '../middlewares/controller.wrapper.js';

const router = Router();
router.route('/')

  /**
   * Retrieve all users.
   * @route GET /users
   * @group Users - Operations on users
   * @returns {Array<Object>} List of users.
   */
  .get(wrapper(projectController.getAll.bind(projectController)));
/**
   * Create a new user.
   * @route POST /users
   * @group Users - Operations on users
   * @param {Object} req.body - User data to create.
   * @returns {Object} The created user.
   */
// .post(wrapper(projectController.createproject.bind(projectController)));

router.route('/:id')
  /**
   * Retrieve a specific user by its ID.
   * @route GET /users/{id}
   * @group Users - Operations on users
   * @param {string} req.params.id - The unique identifier of the user to retrieve.
   * @returns {Object} The requested user.
   */
  .get(wrapper(projectController.getOne.bind(projectController)))
  /**
   * Update an existing user.
   * @route PATCH /users/{id}
   * @group Users - Operations on users
   * @param {string} req.params.id - The unique identifier of the user to update.
   * @param {Object} req.body - Updated user data.
   * @returns {Object} The updated user.
  //  */
// .patch(wrapper(projectController.updateproject.bind(projectController)))

  /**
   * Delete an existing user.
   * @route DELETE /users/{id}
   * @group Users - Operations on users
   * @param {string} req.params.id - The unique identifier of the user to delete.
   * @returns {string} Deletion confirmation message.
   */
  .delete(wrapper(projectController.deleteOne.bind(projectController)));

export default router;
