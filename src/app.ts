import express from 'express';
import cookieParser from 'cookie-parser';



const app = express();

// Middleware to parse JSON bodies
app.use(express.json());
app.use(cookieParser());

// Sample route
app.get('/health', (req, res) => {
    res.status(200).send('Server is healthy');
});

export default app;
