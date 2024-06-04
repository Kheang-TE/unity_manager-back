import Joi from 'joi';

export default Joi.object({
  firstname: Joi.string().min(1).required(),
  lastname: Joi.string().min(1).required(),
  email: Joi.string().email().required(),
  code_color: Joi.string()
    .regex(/^#[a-fA-F0-9]{6}$/)
    .message('Color must be a valid hex color code'),
  password: Joi.string()
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
    )
    .message(
      'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number and one special character',
    )
    .required(),
  confirmation_password: Joi.string().valid(Joi.ref('password')).required(),
});
