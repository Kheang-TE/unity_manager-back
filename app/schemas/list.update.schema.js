import Joi from 'joi';

export default Joi.object({
  name: Joi.string().min(1),
  position: Joi.number().greater(0),
  code_color: Joi.string().length(7),
  project_id: Joi.number().integer().greater(0),
}).min(1);
