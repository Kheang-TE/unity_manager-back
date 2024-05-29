import Jwt from 'jsonwebtoken';
import ApiError from '../errors/api.error.js';
/**
 * Check if the user is authenticated
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware
 * @returns {void}
 */
export default (req, res, next) => {
  try {
    const { token } = req.cookies;
    if (!token) {
      next(new ApiError(401, 'Unauthorized', 'No token provided'));
    }
    const decoded = Jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded) {
      next(new ApiError(401, 'Unauthorized', 'Invalid token'));
    }
    req.user = decoded;
    next();
  } catch (error) {
    next(new ApiError(401, 'Unauthorized', "You don't have access to this resource"));
  }
};
