export default class ApiError extends Error {
  constructor(status, message, name, details) {
    super();
    this.name = name;
    this.status = status;
    this.message = message;
    this.details = details;
  }
}
