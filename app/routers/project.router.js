import { Router } from "express";
import projectController from "../controllers/user.controller.js";
import wrapper from "./../middlewares/controller.wrapper.js";

const router = Router();
export default router;

/**
 * Retrieve all users.
 * @route GET /users
 * @group Users - Operations on users
 * @returns {Array<Object>} List of users.
 */
router.get(
  "/projects",
  wrapper(projectController.getAll.bind(projectController))
);
/**
 * Retrieve a specific user by its ID.
 * @route GET /users/{id}
 * @group Users - Operations on users
 * @param {string} req.params.id - The unique identifier of the user to retrieve.
 * @returns {Object} The requested user.
 */
router.get(
  "/projects/:id",
  wrapper(projectController.getOne.bind(projectController))
);

/**
 * Create a new user.
 * @route POST /users
 * @group Users - Operations on users
 * @param {Object} req.body - User data to create.
 * @returns {Object} The created user.
 */
router.post(
  "/projects",
  wrapper(projectController.createUser.bind(projectController))
);

/**
 * Update an existing user.
 * @route PATCH /users/{id}
 * @group Users - Operations on users
 * @param {string} req.params.id - The unique identifier of the user to update.
 * @param {Object} req.body - Updated user data.
 * @returns {Object} The updated user.
 */
router.patch(
  "/projects/:id",
  wrapper(projectController.updateUser.bind(projectController))
);

/**
 * Delete an existing user.
 * @route DELETE /users/{id}
 * @group Users - Operations on users
 * @param {string} req.params.id - The unique identifier of the user to delete.
 * @returns {string} Deletion confirmation message.
 */
router.delete(
  "/projects/:id",
  wrapper(projectController.deleteOne.bind(userController))
);
