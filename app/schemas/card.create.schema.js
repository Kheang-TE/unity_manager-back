import Joi from 'joi';

export default Joi.object({
  name: Joi.string().min(1).required(),
  content: Joi.string().min(1).required(),
  position: Joi.number().greater(0),
  list_id: Joi.number().integer().greater(0).required(),
});
