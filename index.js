import 'dotenv/config';
import cors from 'cors';
import express from 'express';
// import morgan from 'morgan';
import { createServer } from 'http';
import { Server as WebSocketServer } from 'socket.io';
import cookieParser from 'cookie-parser';
import router from './app/routers/index.js';
import mongooseConnexion from './app/models/mongooseClient.js';
import socketApp from './app/sockets/app.socket.js';

await mongooseConnexion();

const app = express();
const httpServer = createServer(app);

const io = new WebSocketServer(httpServer, {
  cors: {
    origin: process.env.FRONT_URL || 'http://localhost:5173',
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

app.use(cookieParser());
socketApp(io);

const corsOptions = {
  origin: process.env.FRONT_URL || 'http://localhost:5173',
  credentials: true,
  optionsSuccessStatus: 200,
};

app.use((req, res, next) => {
  req.io = io;
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(cors(corsOptions));
// app.use(morgan('combined'));
app.use(router);

const port = process.env.PORT || 3000;
httpServer.listen(port, () => {
  console.log(`Server ready: http://localhost:${port}`);
});
