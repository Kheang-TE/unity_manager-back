// eslint-disable-next-line import/no-unresolved, import/extensions
import { findAllCards } from './dataMapper.js';
import { findOneCard } from './dataMapper.js';

const cardController = {
  getAllLists: async (req, res) => {
    try {
      const cards = await findAllCards();
      res.render('kanban', { cards }); // le nom de la page a choisir !
    } catch (error) {
      // eslint-disable-next-line no-console
      console.log(error);
      res.status(500).send('Une erreur est survenue');
    }
  },

  getOneCard: async (req, res) => {
    const cardId = +req.params;
    try {
      const card = await findOneCard(+cardId);
      res.render('kanban', { card }); // le nom de la page a choisir !
    } catch (error) {
      // eslint-disable-next-line no-console
      console.log(error);
      res.status(500).send('Une erreur est survenue');
    }
  },
};

export default cardController;
