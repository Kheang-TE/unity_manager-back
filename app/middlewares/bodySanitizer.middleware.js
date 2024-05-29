import sanitizeHtml from 'sanitize-html';

/**
 * Sanitize the body of the request
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware
 * @returns {void}
 */
export default (req, res, next) => {
  // for each key in the body object check if it is a string and sanitize it
  Object.keys(req.body).forEach((key) => {
    if (typeof req.body[key] === 'string') {
      req.body[key] = sanitizeHtml(req.body[key]);
    }
  });

  next();
};
