/**
 * Wraps a middleware function with error handling.
 * @param {Function} middleware - The middleware function to be wrapped.
 * @returns {Function} An asynchronous function that wraps around the provided middleware.
 */

export default function controllerWrapper(middleware) {
  return async (req, res, next) => {
    try {
      await middleware(req, res, next);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Unexpected server error' });
    }
  };
}
