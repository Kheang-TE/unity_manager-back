import 'dotenv/config';
import cors from 'cors';
import express from 'express';
import morgan from 'morgan';
import { createServer } from 'http';
import { Server as WebSocketServer } from 'socket.io';
import cookieParser from 'cookie-parser';
import router from './app/routers/index.js';
import mongooseConnexion from './app/models/mongooseClient.js';
import socketApp from './app/sockets/app.socket.js';
import rateLimiter from './app/middlewares/rateLimiter.middleware.js';
import bodySanitizer from './app/middlewares/bodySanitizer.middleware.js';
import swagger from './app/services/swagger/index.js';

await mongooseConnexion();

const app = express();

swagger(app);

const httpServer = createServer(app);

const io = new WebSocketServer(httpServer, {
  cors: {
    origin: 'process.env.FRONT_URL',
    methods: ['GET', 'POST'],
    credentials: true,
  },
});
app.set('trust proxy', 1);
app.use(rateLimiter);
app.use(cookieParser());
socketApp(io);

const corsOptions = {
  origin: 'process.env.FRONT_URL',
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 200,
};

app.use((req, res, next) => {
  req.io = io;
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(bodySanitizer);
app.use(cors(corsOptions));
app.use(morgan('combined'));
app.use(router);

const port = process.env.PORT || 3000;
httpServer.listen(port,'0.0.0.0', () => {
  console.log(`Server ready: http://localhost:${port}`);
});
