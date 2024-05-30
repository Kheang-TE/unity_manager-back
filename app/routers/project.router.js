import { Router } from 'express';
import projectController from '../controllers/project.controller.js';
import wrapper from '../middlewares/controller.wrapper.js';
import createSchema from '../schemas/project.create.schema.js';
import updateSchema from '../schemas/project.update.schema.js';
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
 * @property {string} position.required - The position of the list
 */
/**
 * A Project object with details
 * @typedef {object} ProjectDetails
 * @property {string} name.required - The name of the project
 * @property {string} description - The description of the project
 * @property {array<ListDetails>} lists - The lists of the project
 * @property {array<User>} collaborators - The collaborators of the project
 *
 */
/** A Project object
 * @typedef {object} Project
 * @property {string} id.required - The unique identifier of the project
 * @property {string} name.required - The name of the project
 *
 */
const router = Router();
/**
 * GET /projects/user
 * @summary Get projects by user
 * @tags Projects
 * @return {Array<Project>} 200 - success response - application/json
 * @return {ApiError} 400 - bad input response
 * @return {ApiError} 500 - internal server error response
 * @security JsonWebToken
 */
router.route('/user').get(wrapper(projectController.getProjectByUser));

router.route('/')

/**
 * GET /projects
 * @summary Get all projects
 * @tags Projects
 * @return {Array<Project>} 200 - success response - application/json
 * @return {ApiError} 400 - bad input response
 * @return {ApiError} 500 - internal server error response
 * @security Bearer
 */
  .get(wrapper(projectController.getAll.bind(projectController)))
/**
 * POST /projects
 * @summary Create a new project
 * @tags Projects
 * @param {ProjectDetails} request.body - The project details
 * @return {Project} 200 - success response - application/json
 * @return {ApiError} 400 - bad input response
 * @return {ApiError} 500 - internal server error response
 * @security Bearer
 */
  .post(validationMiddleware(createSchema, 'body'), wrapper(projectController.create.bind(projectController)));

router.route('/:id')
/**
 * GET /projects/{id}
 * @summary Get one project
 * @tags Projects
 * @param {string} req.params.id - The unique identifier of the project
 * @return {Project} 200 - success response - application/json
 * @return {ApiError} 400 - bad input response
 * @return {ApiError} 500 - internal server error response
 * @security Bearer
 */
  .get(wrapper(projectController.getOne.bind(projectController)))
/**
 * PATCH /projects/{id}
 * @summary Update an existing project
 * @tags Projects
 * @param {string} req.params.id - The unique identifier of the project
 * @param {ProjectDetails} request.body - The project details
 * @return {Project} 200 - success response - application/json
 * @return {ApiError} 400 - bad input response
 * @return {ApiError} 500 - internal server error response
 * @security Bearer
 * */
  .patch(validationMiddleware(updateSchema, 'body'), wrapper(projectController.update.bind(projectController)))

/**
 * DELETE /projects/{id}
 * @summary Delete an existing project
 * @tags Projects
 * @param {string} req.params.id - The unique identifier of the project
 * @return {string} 200 - success response - application/json
 * @return {ApiError} 400 - bad input response
 * @return {ApiError} 500 - internal server error response
 * @security Bearer
 */
  .delete(wrapper(projectController.deleteOne.bind(projectController)));

router.route('/:id/details')
/**
 * GET /projects/{id}/details
 * @summary Get one project with details
 * @tags Projects
 * @param {string} req.params.id - The unique identifier of the project
 * @return {ProjectDetails} 200 - success response - application/json
 * @return {ApiError} 400 - bad input response
 * @return {ApiError} 500 - internal server error response
 * @security Bearer
 */
  .get(wrapper(projectController.getProjectWithDetails));

router.route('/:id/collaborators')
/**
 * GET /projects/{id}/collaborators
 *  @summary Get last collaborator of a project
 *  @tags Projects
 *  @param {string} req.params.id - The unique identifier of the project
 *  @return {Collaborator} 200 - success response - application/json
 *  @return {ApiError} 400 - bad input response
 *  @return {ApiError} 500 - internal server error response
 *  @security Bearer
 * */
  .get(wrapper(projectController.getLastCollaborator.bind(projectController)))
/**
 * POST /projects/{id}/collaborators
 *  @summary Add a collaborator to a project
 *  @tags Projects
 *  @param {string} req.params.id - The unique identifier of the project
 *  @param {Collaborator} request.body - The collaborator details
 *  @return {Collaborator} 200 - success response - application/json
 *  @return {ApiError} 400 - bad input response
 *  @return {ApiError} 500 - internal server error response
 *  @security Bearer
 * */
  .post(wrapper(projectController.createCollaborators.bind(projectController)));

export default router;
