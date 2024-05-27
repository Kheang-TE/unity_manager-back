export default (req, res, next) => { req.body.user_id = req.user.id; next(); };
