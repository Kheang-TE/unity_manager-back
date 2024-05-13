import { Router } from "express";
import * as messageController from "../controllers/message.controller.js";
import { controllerWrapper as cw } from "./controlerWrapper.router.js";

export const router = Router();

/**
 * Retrieves all messages.
 * @route GET /messages
 * @group Messages - Operations on messages
 * @returns {Array<Object>} List of messages.
 */
router.get("/messages", cw(messageController.getAllMessages));

/**
 * Retrieves a specific message by its ID.
 * @route GET /messages/{id}
 * @group Messages - Operations on messages
 * @param {string} req.params.id - The unique identifier of the message to retrieve.
 * @returns {Object} The requested message.
 */
router.get("/messages/:id", cw(messageController.getOneMessage));

/**
 * Creates a new message.
 * @route POST /messages
 * @group Messages - Operations on messages
 * @param {Object} req.body - Message data to create.
 * @returns {Object} The created message.
 */
router.post("/messages", cw(messageController.createMessage));

/**
 * Updates an existing message.
 * @route PATCH /messages/{id}
 * @group Messages - Operations on messages
 * @param {string} req.params.id - The unique identifier of the message to update.
 * @param {Object} req.body - Updated message data.
 * @returns {Object} The updated message.
 */
router.patch("/messages/:id", cw(messageController.updateList));

/**
 * Deletes an existing message.
 * @route DELETE /messages/{id}
 * @group Messages - Operations on messages
 * @param {string} req.params.id - The unique identifier of the message to delete.
 * @returns {string} Deletion confirmation message.
 */
router.delete("/messages/:id", cw(messageController.deleteList));
