import { Router } from "express";
import listController from "../controllers/list.controller.js";
import wrapper from "./../middlewares/controller.wrapper.js";

const router = Router();
export default router;
/**
 * Retrieves all lists.
 * @route GET /lists
 * @group Lists - Operations on lists
 * @returns {Array<Object>} List of lists.
 */
router.get("/lists", wrapper(listController.getAll.bind(listController)));

/**
 * Retrieves a specific list by its ID.
 * @route GET /lists/{id}
 * @group Lists - Operations on lists
 * @param {string} req.params.id - The unique identifier of the list to retrieve.
 * @returns {Object} The requested list.
 */
router.get("/lists/:id", wrapper(listController.getOne.bind(listController)));

/**
 * Creates a new list.
 * @route POST /lists
 * @group Lists - Operations on lists
 * @param {Object} req.body - List data to create.
 * @returns {Object} The created list.
 */
router.post("/lists", wrapper(listController.createList.bind(listController)));

/**
 * Updates an existing list.
 * @route PATCH /lists/{id}
 * @group Lists - Operations on lists
 * @param {string} req.params.id - The unique identifier of the list to update.
 * @param {Object} req.body - Updated list data.
 * @returns {Object} The updated list.
 */
router.patch(
  "/lists/:id",
  wrapper(listController.updateList.bind(listController))
);

/**
 * Deletes an existing list.
 * @route DELETE /lists/{id}
 * @group Lists - Operations on lists
 * @param {string} req.params.id - The unique identifier of the list to delete.
 * @returns {string} Deletion confirmation message.
 */
router.delete(
  "/lists/:id",
  wrapper(listController.deleteOne.bind(listController))
);
