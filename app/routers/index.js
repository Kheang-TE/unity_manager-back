// Router principal
import { Router } from 'express';

import listRouter from './list.router.js';
import cardRouter from './card.router.js';
import tagRouter from './tag.router.js';
import userRouter from './user.router.js';
import projectRouter from './project.router.js';
// import { router as messageRouter } from "./message.router.js";

const router = Router();

router.use(listRouter);
router.use(cardRouter);
router.use(tagRouter);
router.use(userRouter);
router.use(projectRouter);
// router.use(messageRouter);

// Middleware 404 (API)
router.use((req, res) => {
  res.status(404).json({ error: 'Ressource not found' });
});

export default router;
