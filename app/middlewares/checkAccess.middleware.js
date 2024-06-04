/**
 * Check if the user has access to the resource
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware
 * @returns {void}
 */

export default async (req, res, next) => {
  const userId = req.user.id;
  const resourceId = req.params.id;

  resourceId.findByPk(resourceId).then((resource) => {
    if (!resource) {
      return res.status(404).json({
        error: 'The requested resource could not be found on the server.',
      });
    }
  });
};
