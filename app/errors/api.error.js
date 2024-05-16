export default class ApiError extends Error {
  /**
   * Constructor for creating a new ApiError instance.
   *
   * @param {any} status - The status code of the error.
   * @param {string} message - The error message.
   * @param {any} details - Additional details about the error.
   */
  constructor(status, message, details) {
    super();
    this.status = status;
    this.message = message;
    this.details = details;
  }
}
