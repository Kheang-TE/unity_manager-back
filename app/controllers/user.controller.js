/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable import/prefer-default-export */
/* eslint-disable no-unused-vars */

import bcrypt from 'bcrypt';
import { User } from '../models/index.js';
import coreController from './core.controller.js';
import ApiError from '../errors/api.error.js';

export default class userController extends coreController {
  static tableName = User;

  /**
  * Creates a new user in the system if all input parameters are valid.
  *
  * @param {Object} req - The request object containing user details.
  * @param {Object} res - The response object for sending the result.
  * @returns {Promise<void>} A promise resolved once the user is created and a response is sent back.
  */
  static async createUser(req, res) {
    const {
      firstname, lastname, email, password, code_color,
    } = req.body;
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      throw new ApiError(409, 'Conflict', 'User with that email already exists.');
    }
    const nbOfSaltRounds = parseInt(process.env.NB_OF_SALT_ROUNDS, 10) || 10;
    const hashedPassword = await bcrypt.hash(password, nbOfSaltRounds);

    const user = await User.create({
      firstname,
      lastname,
      email,
      code_color,
      password: hashedPassword,
    });
    res.status(201).json(user);
  }

  static async updateUser(req, res) {
    const { id } = req.params;
    const {
      firstname, lastname, email, password, code_color,
    } = req.body;
    if (!Number.isInteger(id)) {
      throw new ApiError(400, 'Bad Request', 'The provided ID is not a number');
    }
    const user = await User.findByPk(id);
    if (!user) {
      throw new ApiError(404, 'Not Found', 'User not found');
    }
    const nbOfSaltRounds = parseInt(process.env.NB_OF_SALT_ROUNDS, 10) || 10;
    const hashedPassword = await bcrypt.hash(password, nbOfSaltRounds);

    const isMatching = await bcrypt.compare(password, user.password);
    if (!isMatching) {
      throw new ApiError(401, 'Unauthorized', 'Email or password is incorrect');
    }

    await user.update({
      firstname, lastname, email, password: hashedPassword, code_color,
    });
    return res.json(user);
  }

  static async signIn(req, res) {
    const { email, password } = req.body;

    const user = await User.findOne({ where: { email } });
    if (!user) {
      throw new ApiError(401, 'Unauthorized', 'Email or password is incorrect');
    }

    const isMatching = await bcrypt.compare(password, user.password);
    if (!isMatching) {
      throw new ApiError(401, 'Unauthorized', 'Email or password is incorrect');
    }

    res.status(200).json(user);
  }
}
