import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import morgan from 'morgan';
import router from './app/routers/index.js';
import mongooseConnexion from './app/models/mongooseClient.js';
import { createServer } from "node:http";
import { Server as WebsocketServer } from "socket.io";
import socketApp from "./app/webSocket_chat/socket.app.js";

dotenv.config();

const port = process.env.PORT || '3000';
const app = express();

const server = createServer(app);


await mongooseConnexion();

app.use(express.json());

app.use(express.urlencoded({ extended: true }));
const io = new WebsocketServer(server, {
  cors: { origin: process.env.FRONT_URL || 'http://localhost:5173',
          credentials: true,
          optionsSuccessStatus: 200,}
});

socketApp(io);

app.use(morgan('combined'));
app.use(router);
app.use(cors());
server.listen(port, () => {
  console.log(`Server ready: http://localhost:${port}`);
});
