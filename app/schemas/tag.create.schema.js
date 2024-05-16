import Joi from 'joi';

export default Joi.object({
  name: Joi.string().min(1).required(),
  code_color: Joi.string().regex(/^#[a-fA-F0-9]{6}$/),
});
