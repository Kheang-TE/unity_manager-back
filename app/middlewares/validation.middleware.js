import ApiError from '../errors/api.error.js';

export default (schema, requestProperty) => async (req, _, next) => {
  try {
    await schema.validateAsync(req[requestProperty]);
    next();
  } catch (err) {
    next(new ApiError(400, err.message));
  }
};
