import express from 'express';
import cookieParser from 'cookie-parser';
import authRouter from './routes/auth.routes';


const app = express();

// Middleware to parse JSON bodies
app.use(express.json());
app.use(cookieParser());

// Sample route
app.get('/health', (req, res) => {
    res.status(200).send('Server is healthy');
});

app.use("/api/auth", authRouter);


export default app;
