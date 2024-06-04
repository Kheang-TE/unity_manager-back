import Joi from 'joi';

export default Joi.object({
  email: Joi.string().email().regex(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/).required(),
  password: Joi.string().regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/).message('Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number and one special character').required(),
});
