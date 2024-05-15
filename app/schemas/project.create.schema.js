import Joi from 'joi';

export default Joi.object({
  name: Joi.string().min(1).required(),
  ownerId: Joi.number().integer().greater(0).required(),
});
