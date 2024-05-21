export default () => (req, res, next) => {
  req.io = io;
  next();
};
