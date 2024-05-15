import Joi from 'joi';

export default Joi.object({
  name: Joi.string().min(1),
  owner_Id: Joi.number().integer().greater(0),
}).min(1);
