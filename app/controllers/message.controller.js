import { Message, User } from '../models/index.js';
import ApiError from '../errors/api.error.js';

const messageController = {

  /**
 * Creates a new message with the given input data and user ID.
 *
 * @param {Object} req - The request object containing the user ID and message data.
 * @param {Object} res - The response object to send the created message.
 * @return {Promise<void>} - A promise that resolves when the message is created and sent as a response.
 */
  async create(req, res) {
    const { id } = req.user;
    const input = req.body;
    const newMessage = new Message({ ...input, user_id: id });
    await newMessage.save();
    res.send(newMessage);
  },
  /**
 * Retrieves a single message by its ID.
 *
 * @param {Object} req - The request object containing the message ID.
 * @param {Object} res - The response object to send the message.
 * @param {Function} next - The next middleware function.
 * @return {Promise<void>} - A promise that resolves when the message is retrieved and sent as a response.
 */
  async getOne(req, res, next) {
    const { id } = req.params;
    const message = await Message.findById({ _id: +id });
    if (!message) {
      return next(new ApiError(404, 'Data not found', `Message not found with the provided the ID: ${+id}`));
    }
    res.send(message);
  },
  /**
   * Retrieves all messages from the database and sends them as a response.
   *
   * @param {Object} req - The request object.
   * @param {Object} res - The response object.
   * @return {Promise<void>} A promise that resolves when the messages are retrieved and sent as a response.
   */
  async getAll(req, res) {
    const messages = await Message.find();
    res.send(messages);
  },

  /**
 * Deletes a specific record from the database based on the provided ID.
 *
 * @param {Object} req - The request object containing the ID of the message to delete.
 * @param {Object} res - The response object to send the result of the deletion.
 * @param {Function} next - The next middleware function.
 * @return {Promise<void>} A promise that resolves when the deletion is complete.
 * @throws {ApiError} If the message with the provided ID is not found.
 */
  async deleteOne(req, res, next) {
    const { id } = req.params;
    const message = await Message.findById({ _id: id });
    if (!message) {
      return next(new ApiError(404, 'Data not found', `${Message.name} not found with the provided the ID: ${id}`));
    }
    await message.deleteOne();
    res.send({ message: `${Message.name} deleted successfully!` });
  },
  /**
 * Updates a message in the database with the provided ID using the data from the request body.
 *
 * @param {Object} req - The request object containing the ID of the message to update and the updated data.
 * @param {Object} res - The response object to send the updated message.
 * @return {Promise<void>} A promise that resolves when the message is successfully updated and sent as a response.
 */
  async update(req, res) {
    const { id } = req.params;
    await Message.findByIdAndUpdate(id, { ...req.body });
    const newMessage = await Message.findById({ _id: id });
    res.send(newMessage);
  },
  /**
 * Retrieves all messages from the database that belong to a specific project.
 *
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @return {Promise<void>} A promise that resolves when the messages are retrieved and sent as a response.
 */
  async getByProjectId(req, res, next) {
    const { id } = req.params;
    if (!id || typeof id !== 'string') {
      next(new ApiError(400, 'Bad Request', 'Invalid project ID'));
    }

    try {
      const messages = await Message.find({ project_id: id });
      if (!messages.length) {
        next(new ApiError(404, 'Data not found', 'No messages found for the provided project ID'));
      }

      const messagesWithUser = await Promise.all(messages.map(async (message) => {
        try {
          const user = await User.findByPk(message.user_id);
          return { ...message.toJSON(), user: user ? { firstname: user.firstname, lastname: user.lastname, color: user.code_color } : null };
        } catch (error) {
          console.error('Error while getting user:', error);
          return { ...message.toJSON(), user: null };
        }
      }));

      res.send(messagesWithUser);
    } catch (error) {
      console.error('Error while getting messages:', error);
      res.status(500).json({ message: 'Internal Server Error', error: 'An unexpected error occurred' });
    }
  },
  /**
 * Retrieves all messages associated with a user based on the provided user ID.
 *
 * @param {Object} req - The request object containing the user ID.
 * @param {Object} res - The response object to send the retrieved messages.
 * @return {Promise<void>} A promise that resolves when the messages are successfully retrieved and sent as a response.
 */
  async getByUserId(req, res) {
    const { id } = req.params;
    const messages = await Message.findAll({ where: { user_id: id } });
    res.send(messages);
  },
};
export default messageController;
