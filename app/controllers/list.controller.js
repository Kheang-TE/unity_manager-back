// eslint-disable-next-line import/no-unresolved, import/extensions
import { findAllLists } from './dataMapper.js';
import { findOneList } from './dataMapper.js';

const listController = {
  getAllLists: async (req, res) => {
    try {
      const lists = await findAllLists();
      res.render('kanban', { lists }); // le nom de la page a choisir !
    } catch (error) {
      // eslint-disable-next-line no-console
      console.log(error);
      res.status(500).send('Une erreur est survenue');
    }
  },

  getOneCard: async (req, res) => {
    const listId = +req.params;
    try {
      const list = await findOneList(+listId);
      res.render('kanban', { list }); // le nom de la page a choisir !
    } catch (error) {
      // eslint-disable-next-line no-console
      console.log(error);
      res.status(500).send('Une erreur est survenue');
    }
  },
};

export default listController;
