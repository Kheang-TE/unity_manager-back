/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable import/prefer-default-export */
/* eslint-disable no-unused-vars */

import bcrypt from 'bcrypt';
import Jwt from 'jsonwebtoken';
import {
  Card, List, Project, Tag, User,
} from '../models/index.js';
import coreController from './core.controller.js';
import ApiError from '../errors/api.error.js';

export default class userController extends coreController {
  static tableName = User;

  static stringTableName = 'User';

  /**
   * Creates a new user in the system if all input parameters are valid.
   *
   * @param {Object} req - The request object containing user details.
   * @param {Object} res - The response object for sending the result.
   * @returns {Promise<void>} A promise resolved once the user is created and a response is sent back.
   * @throws {ApiError} If a user with the same email already exists.
   */
  static async createUser(req, res, next) {
    const {
      firstname,
      lastname,
      email,
      password,
      code_color,
    } = req.body;
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      next(
        new ApiError(409, 'Conflict', 'User with that email already exists.'),
      );
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

  /**
   * Updates a user's information in the database.
   *
   * @param {Object} req - The request object containing the user's ID and updated information.
   * @param {Object} res - The response object to send the updated user.
   * @throws {ApiError} If the provided ID is not a number or if the user is not found.
   * @throws {ApiError} If the provided password is incorrect.
   * @return {Promise<void>} The updated user as a JSON response.
   */
  static async updateUser(req, res, next) {
    const userId = +req.user.id;
    const {
      firstname,
      lastname,
      email,
      new_password,
      actual_password,
      code_color,
    } = req.body;
    if (!Number.isInteger(userId)) {
      return next(
        new ApiError(400, 'Bad Request', 'The provided ID is not a number'),
      );
    }
    const user = await User.findByPk(userId);
    if (!user) {
      return next(new ApiError(404, 'Not Found', 'User not found'));
    }
    const numberOfSaltRounds = parseInt(process.env.NB_OF_SALT_ROUNDS, 10) || 10;

    const isPasswordMatch = await bcrypt.compare(actual_password, user.password);
    if (!isPasswordMatch) {
      return next(
        new ApiError(401, 'Unauthorized', 'Email or password is incorrect'),
      );
    }

    const updatedUser = await user.update({
      firstname,
      lastname,
      email,
      password: new_password
        ? await bcrypt.hash(new_password, numberOfSaltRounds)
        : user.password,
      code_color,
    });

    return res.json(updatedUser);
  }

  /**
   * Sign in a user with the provided email and password.
   *
   * @param {Object} req - The request object containing the email and password.
   * @param {Object} res - The response object for sending the result.
   * @param {Function} next - The next middleware function.
   * @returns {Promise<void>} A promise resolved once the user is signed in and a response is sent back.
   * @throws {ApiError} If the email or password is incorrect.
   */
  static async signIn(req, res, next) {
    const { email, password } = req.body;

    const user = await User.findOne({ where: { email } });
    if (!user) {
      return next(
        new ApiError(401, 'Unauthorized', 'Email or password is incorrect'),
      );
    }

    const isMatching = await bcrypt.compare(password, user.password);
    if (!isMatching) {
      return next(
        new ApiError(401, 'Unauthorized', 'Email or password is incorrect'),
      );
    }

    const accessToken = Jwt.sign({ id: user.id }, process.env.JWT_SECRET);
    res.cookie('token', accessToken, {
      httpOnly: true, // Le cookie n'est pas accessible via JavaScript côté client
      secure: false, // Le cookie est envoyé uniquement sur des connexions HTTPS
      maxAge: 24 * 60 * 60 * 1000, // Temps d'expiration du cookie en millisecondes
      sameSite: 'strict', // Le cookie est envoyé uniquement avec des requêtes du même site
    });

    return res.json({
      id: user.id, firstname: user.firstname, lastname: user.lastname, id: user.id, email: user.email, code_color: user.code_color,
    });
  }

  static async signOut(req, res) {
    res.clearCookie('token', {
      httpOnly: true,
      secure: false,
      sameSite: 'strict',
    });
    res.status(200).json({ message: 'Sign out successful' });
  }

  /**
   * Retrieves the user board for the authenticated user.
   *
   * @param {Object} req - The request object.
   * @param {Object} res - The response object.
   * @param {Function} next - The next middleware function.
   * @return {Promise<Object>} The user board data.
   * @throws {ApiError} If the provided ID is not a number.
   */
  static async getUserBoard(req, res, next) {
    const id = +req.user.id;
    if (!Number.isInteger(id)) {
      return next(
        new ApiError(400, 'Bad Request', 'The provided ID is not a number'),
      );
    }
    const result = await User.findByPk(id, {
      include: [
        {
          model: Project,
          as: 'projects',
          through: { attributes: [] },
          include: [
            {
              model: User, // Les collaborateurs des projets
              attributes: ['id', 'firstname', 'lastname'],
              as: 'collaborators',
              through: { attributes: [] },
            },
            {
              model: List, // Les listes du projet
              attributes: ['id', 'name', 'position', 'code_color'],
              as: 'lists',
              include: [
                {
                  model: Card, // Les cartes des listes
                  attributes: ['id', 'name', 'content', 'position'],
                  as: 'cards',
                  include: [
                    {
                      model: User, // L'utilisateur associé à chaque carte
                      attributes: ['firstname', 'lastname'],
                      through: { attributes: [] },
                      as: 'users',
                    },
                    {
                      model: Tag, // Les tags des cartes
                      attributes: ['id', 'name', 'code_color'],
                      through: { attributes: [] },
                      as: 'tags',
                    },
                  ],
                },
              ],
            },
          ],
        },
      ],
    });
    return res.json(result);
  }
}
