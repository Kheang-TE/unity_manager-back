import 'dotenv/config';

import { Sequelize } from 'sequelize';

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
    console.log('Connection has been established successfully.');
  } catch (error) {
    console.error('Unable to connect to the database:', error);
  }
})();

export default sequelize;