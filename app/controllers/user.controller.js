/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable import/prefer-default-export */
/* eslint-disable no-unused-vars */

import bcrypt from 'bcrypt';
import emailValidator from 'email-validator';
import Joi from 'joi';
import { User } from '../models/index.js';

/**
 * Retrieves all users from the database and returns them.
 *
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 * @return {Object} The list of users or an error message
 */
export async function getAllUsers(req, res) {
  const users = await User.findAll();
  if (!users) {
    res.status(404).json({
      error: 'The requested resource could not be found on the server.',
    });
    return;
  }
  res.status(200).json(users);
}

/**
 * Retrieves a single user based on the provided ID.
 *
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 * @return {Object} The user object or an error message
 */
export async function getOneUser(req, res) {
  const userId = +req.params.id;
  if (!Number.isInteger(userId)) {
    res.status(404).json({
      error: 'The requested resource could not be found on the server.',
    });
    return;
  }
  const user = await User.findByPk(userId);
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }
  res.status(200).json(user);
}

/**
 * Creates a new user in the system if all input parameters are valid.
 *
 * @param {Object} req - The request object containing user details.
 * @param {Object} res - The response object for sending the result.
 * @returns {Promise<void>} A promise resolved once the user is created and a response is sent back.
 */
export async function createUser(req, res) {
  const {
    firstname, lastname, email, password, confirmation,
  } = req.body;
  if (!firstname || !lastname || !email || !password || !confirmation) {
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
  await User.create({
    firstname,
    lastname,
    email,
    password: hashedPassword,
  });
  const schema = Joi.object({
    firstname: Joi.string().min(1).required(),
    lastname: Joi.string().min(1).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(8).required(),
    confirmation: Joi.string().valid(Joi.ref('password')).required(),
  });
  const { error } = schema.validate(req.body);
  if (error) {
    res.status(400).json({ error: error.message });
    return;
  }
  const user = await User.create({
    firstname,
    lastname,
    email,
    password,
  });
  res.status(201).json(user);
}
