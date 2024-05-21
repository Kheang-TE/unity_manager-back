import "dotenv/config";
import { Server as WebsocketServer } from "socket.io";
import { createServer } from "node:http";
import expressApp from "./index.app.js";
import socketApp from "./socket.app.js";
import cors from "cors";
import app from "./index.app.js";

const httpServer = createServer(expressApp); 
const io = new WebsocketServer(httpServer, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});

socketApp(io);

app.use(cors());

const PORT = process.env.PORT || 4000;

httpServer.listen(PORT, () => {
  console.log(`🚀 server running at http://localhost:${PORT}`);
});
