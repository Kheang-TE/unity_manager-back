import Joi from 'joi';

export default Joi.object({
  firstname: Joi.string().min(1),
  lastname: Joi.string().min(1),
  email: Joi.string().email(),
  code_color: Joi.string(),
  password: Joi.string().min(8).required(),
  confirmation: Joi.string().valid(Joi.ref('password')).required(),
}).min(1);
