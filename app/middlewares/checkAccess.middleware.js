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
