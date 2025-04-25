import express from 'express';
import dotenv from "dotenv";
import authRoutes from './routes/authRoutes'; 

const app = express();

app.use(express.json());

dotenv.config();

if (!process.env.JWT_SECRET) {
  console.error("Error: JWT_SECRET must be defined in .env");
  process.exit(1);
}
app.use('/auth', authRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
