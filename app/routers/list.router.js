import { Router } from 'express';
import listController from '../controllers/list.controller.js';
import wrapper from '../middlewares/controller.wrapper.js';
import createSchema from '../schemas/list.create.schema.js';
import updateSchema from '../schemas/list.update.schema.js';
import validationMiddleware from '../middlewares/validation.middleware.js';
/**
 * A api success object
 * @typedef {object} ApiSuccess
 * @property {string} status - The Json status Property
 * @property {object} data - The data object
 */

/**
 * A api error object
 * @typedef {object} ApiError
 * @property {string} status - The error code
 * @property {string} message - The error message
 * @property {string} details - The error details
 */
/**
 * A User object
 * @typedef {object} User
 * @property {string} firstname.required - User's username - eg: john
 * @property {string} lastname.required - User's lastname - eg: doe
 * @property {string} email.required - User's email - eg: john.doe@example.com
 * @property {string} code_color - User's code color - eg: #ffffff
 */
/**
 * A Tag object
 * @typedef {object} Tag
 * @property {string} name.required - The name of the tag
 * @property {string} code_color.required - The hexadecimal code color of the tag
 */
/**
 * A Card object with details
  * @typedef {object} CardDetails
 * @property {string} name.required - The name of the card
 * @property {string} content - The content of the card
 * @property {string} position.required - The position of the card
 * @property {string} list_id.required - The list ID of the card
 * @property {array<User>} users- The user ID of the card
 * @property {array<Tag>} tags - The tags of the card
 */

/**
 * A list object with details
 * @typedef {object} ListDetails
 * @property {string} name.required - The name of the list
 * @property {string} position.required - The position of the list
 * @property {string} code_color.required - The hexadecimal code color of the list
 * @property {array<CardDetails>} cards - The cards of the list
 */
/**
 * A List object
 * @typedef {object} List
 * @property {string} id.required - The unique identifier of the list
 * @property {string} name.required - The name of the list
 * @property {string} code_color.required - The hexadecimal code color of the list
 * @property {string} position.required - The position of the list
 */
const router = Router();

router
  .route('/')
  /**
 * GET /lists
 * @summary Get all lists
 * @tags Lists
 * @return {Array<Lists>} 200 - success response - application/json
 * @return {ApiError} 400 - bad input response
 * @return {ApiError} 500 - internal server error response
 * @security bearer
 */
  .get(wrapper(listController.getAll.bind(listController)))
  /**
   * POST /lists
   * @summary Create a new list
   * @tags Lists
   * @param {Object} request.body - List data to create.
   * @returns {list} 201 - created response
   * @returns {ApiError} 400 - bad input response
   * @returns {ApiError} 500 - internal server error response
   * @security bearer
   */
  .post(validationMiddleware(createSchema, 'body'), wrapper(listController.create.bind(listController)));

router.route('/:id')
  /**
   * GET /lists/{id}
   * @summary Get one list
   * @tags Lists
   * @param {string} req.params.id - The unique identifier of the list
   * @return {List} 200 - success response - application/json
   * @return {ApiError} 400 - bad input response
   * @return {ApiError} 500 - internal server error response
   * @security bearer
   * */
  .get(wrapper(listController.getOne.bind(listController)))

  /**
   * PATCH /lists/{id}
   * @summary Update one list
   * @tags Lists
   * @param {string} req.params.id - The unique identifier of the list
   * @return {List} 200 - success response - application/json
   * @return {ApiError} 400 - bad input response
   * @return {ApiError} 500 - internal server error response
   * @security bearer
   */
  .patch(validationMiddleware(updateSchema, 'body'), wrapper(listController.update.bind(listController)))

  /**
   * DELETE /lists/{id}
   * @summary Delete one list
   * @tags Lists
   * @param {string} req.params.id - The unique identifier of the list
   * @return {List} 200 - success response - application/json
   * @return {ApiError} 400 - bad input response
   * @return {ApiError} 500 - internal server error response
   * @security bearer
   */
  .delete(wrapper(listController.deleteOne.bind(listController)));

router.route('/projects/:id')
  /**
   * GET /lists/projects/{id}
   * @summary Get all lists by project
   * @tags Lists
   * @param {string} req.params.id - The unique identifier of the project
   * @return {Array<ListDetails>} 200 - success response - application/json
   * @return {ApiError} 400 - bad input response
   * @return {ApiError} 500 - internal server error response
   * @security bearer
   */
  .get(wrapper(listController.getByProjectId.bind(listController)));
export default router;
