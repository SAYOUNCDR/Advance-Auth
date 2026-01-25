import express from "express";
import dotenv from "dotenv";
import connectDB from "./config/db.js";
import userRoutes from "./routes/userRoutes.js";
dotenv.config();
await connectDB();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.use("/api/v1", userRoutes);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
