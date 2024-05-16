import Joi from 'joi';

export default Joi.object({
  name: Joi.string().min(1).required(),
  owner_id: Joi.number().integer().greater(0).required(),
});
