import mongoose from 'mongoose';

/**
* Middleware to handle errors and return the appropriate status code and message.
*/
export default (err, req, res, next) => {
  let {
    status, message, details,
  } = err;
  const code = err.original?.code || err.parent?.code || err.code;

  if (code === '23505') {
    status = 400;
    message = 'Resource already exists';
    details = err.original?.detail || err.parent?.detail;
  }
  if (code === '23503') {
    status = 400;
    message = 'Foreign_key_violation';
    details = err.original?.detail || err.parent?.detail;
  }

  // Mongoose error: Check if the error is a cast error and if the path is '_id'
  if (err instanceof mongoose.Error.CastError && err.path === '_id') {
    return res.status(400).json({ message: 'Invalid ID format' });
  }

  if (!status) {
    status = 500;
  }

  if (status === 500) {
    if (process.env.NODE_ENV !== 'production') {
      console.error(err);
    }

    message = 'Internal Server Error';
  }

  if (res.format === 'html') {
    return res.status(status).render('error', {
      httpStatus: status,
      message,
    });
  }

  return res.status(status).json({
    status, error: message, details,
  });
};
