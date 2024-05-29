import { Message } from '../models/index.js';
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
 * @return {Promise<void>} - A promise that resolves when the message is retrieved and sent as a response.
 */
  async getOne(req, res) {
    const { id } = req.params;
    const message = await Message.findById({ _id: id });
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
   * @return {Promise<void>} A promise that resolves when the deletion is complete.
   * @throws {ApiError} If the message with the provided ID is not found.
   */
  async deleteOne(req, res) {
    const { id } = req.params;
    const message = await Message.findById({ _id: id });
    if (!message) {
      throw new ApiError(404, 'Data not found', `${Message.name} not found with the provided the ID: ${id}`);
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
  async getByProjectId(req, res) {
    const { id } = req.params;
    console.log('id de la requête get by project id :', req.params.id);
    const messages = await Message.find({ project_id: id });
    res.send(messages);
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
