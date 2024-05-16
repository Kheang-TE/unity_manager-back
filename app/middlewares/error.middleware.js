/**
 * @typedef {object} ApiJsonError - Error response
 * @property {string} error.required - Error message
 * @example
 * {
 *  "error": "Bad request"
 * }
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
