import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import router from './routers/index.js';
import mongooseConnexion from './models/mongooseClient.js';

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

export default app;
