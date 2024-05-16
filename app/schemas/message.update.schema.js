import Joi from 'joi';

export default Joi.object({
  content: Joi.string(),
  project_id: Joi.number().integer().greater(0),
  user_id: Joi.number().integer().greater(0),
}).min(1);
