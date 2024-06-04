import { Router } from 'express';
import userController from '../controllers/user.controller.js';
import wrapper from '../middlewares/controller.wrapper.js';
import createSchema from '../schemas/user.create.schema.js';
import updateSchema from '../schemas/user.update.schema.js';
import signinSchema from '../schemas/user.signin.schema.js';
import authMiddleware from '../middlewares/authentification.middleware.js';
import validationMiddleware from '../middlewares/validation.middleware.js';
/**
 * A User object
 * @typedef {object} UserInput
 * @property {string} firstname.required - User's username - eg: john
 * @property {string} lastname.required - User's lastname - eg: doe
 * @property {string} email.required - User's email - eg: john.doe@example.com
 * @property {string} code_color - User's code color - eg: #ffffff
 * @property {string} password.required - User's password - eg: password123
 * @property {string} confirm_password.required - User's password confirmation - eg: password123
 */
/**
 * A login object
 * @typedef {object} SigninInput
 * @property {string} email.required - User's email - eg: john.doe@example.com
 * @property {string} password.required - User's password - eg: password123
 */

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

const router = Router();
router
  .route('/')
/**
 * GET /users
 * @summary search users
 * @tags Users
 * @param {string} query.query.required - search query
 * @return {Array<UserInput>} 200 - success response
 * @return {ApiError} 400 - bad input response
 * @return {ApiError} 500 - internal server error response
 */
  .get(authMiddleware, wrapper(userController.getAll.bind(userController)))

/**
 * POST /users
 * @summary Register a user
 * @tags Users
 * @param {UserInput} request.body.required - user info
 * @return {ApiSuccess} 200 - success response
 * @return {ApiError} 400 - bad input response
 * @return {ApiError} 500 - internal server error response
 */
  .post(validationMiddleware(createSchema, 'body'), wrapper(userController.createUser.bind(userController)));

router.route('/signin')

/**
   * POST /users/signin
   * @summary Login a user
   * @tags Users
   * @param {SignIninput} request.body.required - user info
   * @return {ApiSuccess} 200 - success response
   * @return {ApiError} 400 - bad input response
   * @return {ApiError} 500 - internal server error response
   */

  .post(validationMiddleware(signinSchema, 'body'), wrapper(userController.signIn.bind(userController)));

router.route('/signout')
  /**
   * POST /users/signout
   * @summary Logout a user
   * @tags Users
   * @return {ApiSuccess} 200 - success response
   * @return {ApiError} 400 - bad input response
   * @return {ApiError} 500 - internal server error response
   * */
  .get(authMiddleware, wrapper(userController.signOut.bind(userController)));

router.route('/:id')

/**
  * GET /users/{id}
  * @summary Get a user by id
  * @tags Users
  * @param {string} req.params.id - The unique identifier of the user.
  * @return {UserInput} 200 - success response
  * @return {ApiError} 400 - bad input response
  * @return {ApiError} 500 - internal server error response
  */
  .get(authMiddleware, wrapper(userController.getOne.bind(userController)))
  /**
   * PATCH /users/{id}
   * @summary Update a user
   * @tags Users
   * @param {string} req.params.id - The unique identifier of the user.
   * @param {UserInput} request.body.required - user info
   * @return {ApiSuccess} 200 - success response
   * @return {ApiError} 400 - bad input response
   * @return {ApiError} 500 - internal server error response
   */
  .patch(authMiddleware, validationMiddleware(updateSchema, 'body'), wrapper(userController.updateUser.bind(userController)))

  /**
   * DELETE /users/{id}
   * @summary Delete a user
   * @tags Users
   * @param {string} req.params.id - The unique identifier of the user.
   * @return {ApiSuccess} 200 - success response
   * @return {ApiError} 400 - bad input response
   * @return {ApiError} 500 - internal server error response
   */
  .delete(authMiddleware, wrapper(userController.deleteOne.bind(userController)));

export default router;
