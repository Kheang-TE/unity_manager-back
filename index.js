import express from 'express';
import router from './app/routers/routers.js';

require('dotenv').config();

const port = process.env.PORT || '3000';
const app = express();

app.use(express.json());

app.use(express.urlencoded({ extended: true }));

app.use(router);

app.listen(port, () => {
  console.log(`Server ready: http://localhost:${port}`);
});
