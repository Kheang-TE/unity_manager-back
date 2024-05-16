import Joi from 'joi';

export default Joi.object({
  content: Joi.string().required(),
  project_id: Joi.number().integer().greater(0).required(),
  user_id: Joi.number().integer().greater(0).required(),
});
