import Joi from 'joi';

export default Joi.object({
  firstname: Joi.string().min(1),
  lastname: Joi.string().min(1),
  email: Joi.string().email().regex(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/),
  code_color: Joi.string().regex(/^#[a-fA-F0-9]{6}$/).message('Color must be a valid hex color code'),
  new_password: Joi.string().regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/).message('Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number and one special character'),
  confirm_new_password: Joi.string().regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/).message('Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number and one special character').valid(Joi.ref('new_password')),
  password: Joi.string().min(8).required(),
}).min(2);
