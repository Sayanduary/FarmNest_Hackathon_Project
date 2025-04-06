import dotenv from 'dotenv';
import { connectDB } from './config/conectDB.js';
import { app } from './app.js';

dotenv.config({
  path: './.env'
})


connectDB()
  .then(() => {
    app.on('Error', (error) => {
      console.log('Error', error);
      throw error;
    })
    app.listen(process.env.PORT || 8000, () => {
      console.log(`Server is running at Port : ${process.env.PORT}`)
    })
  }).catch((error) => {
    console.log("MongoDB  Connection failed", error);
  })

