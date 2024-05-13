// Router principal
import { Router } from "express";

import { router as listRouter } from "./list.router.js";
import { router as cardRouter } from "./card.router.js";
import { router as tagRouter } from "./tag.router.js";
import { router as userRouter } from "./user.router.js";
import { router as messageRouter } from "./message.router.js";

export const router = Router();

router.use(listRouter);
router.use(cardRouter);
router.use(tagRouter);
router.use(userRouter);
router.use(messageRouter);

// Middleware 404 (API)
router.use((req, res) => {
  res.status(404).json({ error: "Ressource not found" });
});
