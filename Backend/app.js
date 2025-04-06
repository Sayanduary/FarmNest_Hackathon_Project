import express from 'express'
import cors from 'cors';
import cookieParser from 'cookie-parser'
import morgan from 'morgan'
import helmet from 'helmet'

const app = express();

app.use(cors({
  credentials: true,
  origin: process.env.FRONTEND_URL
}))
app.use(express.json())
app.use(cookieParser())
app.use(morgan())
app.use(helmet({
  crossOriginResourcePolicy: false
}))

import userRouter from './routes/user.route.js';

app.use('/api/user', userRouter);
app.use("/api/category",categoryRouter)
app.use("/api/file",uploadRouter)
app.use("/api/subcategory",subCategoryRouter)
app.use("/api/product",productRouter)
app.use("/api/cart",cartRouter)
app.use("/api/address",addressRouter)
app.use('/api/order',orderRouter)


export { app }