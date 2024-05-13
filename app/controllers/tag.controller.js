// eslint-disable-next-line import/no-unresolved, import/extensions
import { findAllTags } from './dataMapper.js';
import { findOneTag } from './dataMapper.js';

const tagController = {
  getAllTags: async (req, res) => {
    try {
      const tags = await findAllTags();
      res.render('kanban', { tags }); // le nom de la page a choisir !
    } catch (error) {
      // eslint-disable-next-line no-console
      console.log(error);
      res.status(500).send('Une erreur est survenue');
    }
  },

  getOneTag: async (req, res) => {
    const tagId = +req.params;
    try {
      const tag = await findOneTag(+tagId);
      res.render('kanban', { tag }); // le nom de la page a choisir !
    } catch (error) {
      // eslint-disable-next-line no-console
      console.log(error);
      res.status(500).send('Une erreur est survenue');
    }
  },
};

export default tagController;
