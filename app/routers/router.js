import { Router } from 'express';
import projectDatamapper from '../dataMappers/project.datamapper.js';

const router = Router();

router.get('/:id', async (req, res) => {
  const id = +req.params.id;
  console.log(id);
  const result = await projectDatamapper.findDetailsProject(id);
  console.log(result);

  res.json(result);
});
export default router;
