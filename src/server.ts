import { connectDB } from "./config/db";
import app from "./app";

import dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

async function startServer() {
    // Connect to the database
    await connectDB();

    app.listen(process.env.PORT || 3000, () => {
        console.log(`Server is running on port ${process.env.PORT || 3000}`);
    });
}

startServer().catch((error) => {
    console.error("Failed to start server:", error);
    process.exit(1);
});