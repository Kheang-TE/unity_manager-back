import Jwt from 'jsonwebtoken';
import ApiError from '../errors/api.error.js';

export default (req, res, next) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    if (!token) {
      throw new ApiError(401, 'Unauthorized', 'No token provided');
    }
    const decoded = Jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded) {
      throw new ApiError(401, 'Unauthorized', 'Invalid token');
    }
    req.user = decoded;
    next();
  } catch (error) {
    next(new ApiError(401, 'Unauthorized', "You don't have access to this resource"));
  }
};
