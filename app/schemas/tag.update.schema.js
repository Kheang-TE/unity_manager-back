import Joi from 'joi';

export default Joi.object({
  name: Joi.string().min(1),
  code_color: Joi.string().length(7),
}).min(1);
