/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable import/prefer-default-export */
/* eslint-disable no-unused-vars */

import bcrypt from 'bcrypt';
import { User } from '../models/index.js';
import coreController from './core.controller.js';

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
      firstname, lastname, email, password, code_color, confirmation,
    } = req.body;
    if (!firstname || !lastname || !email || !password || !code_color || !confirmation) {
      res.status(400).json({ error: 'Missing body parameter(s).' });
      return;
    }
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      res.status(409).json({ error: 'User with that email already exists.' });
      return;
    }
    const nbOfSaltRounds = parseInt(process.env.NB_OF_SALT_ROUNDS, 10) || 10;
    const hashedPassword = await bcrypt.hash(password, nbOfSaltRounds);

    const user = await User.create({
      firstname,
      lastname,
      email,
      password: hashedPassword,
    });
    res.status(201).json(user);
  }
}
