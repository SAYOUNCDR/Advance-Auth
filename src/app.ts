import express from 'express';
import cookieParser from 'cookie-parser';
import { registerHandler } from './controllers/auth/auth.controller';



const app = express();

// Middleware to parse JSON bodies
app.use(express.json());
app.use(cookieParser());

// Sample route
app.get('/health', (req, res) => {
    res.status(200).send('Server is healthy');
});


app.post("/register", registerHandler);

export default app;
