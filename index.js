import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import morgan from 'morgan';
import router from './app/routers/index.js';
import mongooseConnexion from './app/models/mongooseClient.js';

dotenv.config();

const port = process.env.PORT || '3000';
const app = express();

await mongooseConnexion();

app.use(express.json());

app.use(express.urlencoded({ extended: true }));
const corsOptions = {
  origin: process.env.FRONT_URL || 'http://localhost:5173',
  credentials: true,
  optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));
app.use(morgan('combined'));
app.use(router);

app.listen(port, () => {
  console.log(`Server ready: http://localhost:${port}`);
});
