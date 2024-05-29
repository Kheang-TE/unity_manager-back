import { rateLimit } from 'express-rate-limit';

const rateLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again after 10 minutes',
});

export default rateLimiter;
