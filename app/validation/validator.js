import ApiError from "../errors/api.error.js";
/**
 * Validates the incoming request data based on a schema and handles errors.
 *
 * @param {object} schema - The Joi schema used for validation
 * @param {string} source - The key in the request object where the data to validate is located
 * @return {function} Middleware function to validate request data and handle errors
 */
export default function validate(schema, source) {
  return (request, response, next) => {
    const { error } = schema.validate(request[source]);
    if (error) {
      const apiError = new ApiError.STATUS(error.name, error.message);
      next(apiError);
    }
    next();
  };
}
