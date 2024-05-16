import mongoose from 'mongoose';

const MessageSchema = new mongoose.Schema(
  {
    content: { type: String, required: true },
    user_id: { type: Number, required: true },
    project_id: { type: Number, required: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
  },
  {
    timestamps: true,
  },
);

const Message = mongoose.model('Message', MessageSchema);

export default Message;
