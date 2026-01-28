import express from 'express';
import cookieParser from 'cookie-parser';
import authRouter from './routes/auth.routes';
import userRouter from './routes/user.route';
import adminRouter from './routes/admin.route';

const app = express();

// Middleware to parse JSON bodies
app.use(express.json());
app.use(cookieParser());

// Sample route
app.get('/health', (req, res) => {
    res.status(200).send('Server is healthy');
});

app.use("/auth", authRouter);
app.use("/user", userRouter);
app.use("/admin", adminRouter);

export default app;
