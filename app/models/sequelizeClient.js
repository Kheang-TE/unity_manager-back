import 'dotenv/config';

import Sequelize from 'sequelize';

const sequelize = new Sequelize(process.env.PG_URL, {
  define: {
    createdAt: 'created_at',
    updatedAt: 'updated_at',
  },
  logging: false,
});

(async () => {
  try {
    await sequelize.authenticate();
    console.log('Connected to the postgres database.');
  } catch (error) {
    console.error('Unable to connect to the postgres database:', error);
  }
})();

export default sequelize;
