import 'dotenv/config';
import { createServer } from 'node:http';
import expressServer from './app/index.app.js';

const port = process.env.PORT || '3000';

const httpServer = createServer(expressServer);

httpServer.listen(port, () => {
  console.log(`Server ready: http://localhost:${port}`);
});
