import express from 'express';
import dotenv from 'dotenv';
import router from './app/routers/index.js';

dotenv.config();

const port = process.env.PORT || '3000';
const app = express();

app.use(express.json());

app.use(express.urlencoded({ extended: true }));

app.use(router);

app.listen(port, () => {
  console.log(`Server ready: http://localhost:${port}`);
});
