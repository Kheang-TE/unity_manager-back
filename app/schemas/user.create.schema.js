import Joi from 'joi';

export default Joi.object({
  firstname: Joi.string().min(1).required(),
  lastname: Joi.string().min(1).required(),
  email: Joi.string().email().required(),
  code_color: Joi.string().required(),
  password: Joi.string().min(8).required(),
  confirmation: Joi.string().valid(Joi.ref('password')).required(),
});
