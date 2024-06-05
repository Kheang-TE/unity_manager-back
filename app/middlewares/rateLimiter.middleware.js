
import { rateLimit } from 'express-rate-limit';

const rateLimiter = rateLimit({
  windowMs: 3 * 60 * 1000, // 3 minutes
  max: 400,
  message: 'Too many requests, please try again after 3 minutes',
});

export default rateLimiter;
