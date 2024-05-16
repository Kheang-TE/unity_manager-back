import 'dotenv/config';
import mongoose from 'mongoose';

const mongooseConnexion = async () => {
  console.log('Connecting to MongoDB...');
  try {
    await mongoose.connect(process.env.MONGODB_URI);

    console.log('Connected to MongoDB');
  } catch (error) {
    console.error('Error connecting to MongoDB:', error.message);
  }
};

export default mongooseConnexion;
