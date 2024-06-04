import Joi from 'joi';

export default Joi.object({
  name: Joi.string().min(1),
  code_color: Joi.string().regex(/^#[a-fA-F0-9]{6}$/).message('Color must be a valid hex color code'),
}).min(1);
