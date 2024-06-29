// import mongoose from "mongoose";
// import express from "express";
// import { DB_NAME } from "./constants";

// const app = express();

// (async () => {
// 	try {
// 		await mongoose.connect(`${process.env.MONGO_DB_URL}/${DB_NAME}`);
// 		app.on("errror", () => {
// 			console.log(error);
// 			throw error;
// 		});
// 		app.listen(process.env.PORT, () => {
// 			console.log(`App is listening on the port ${process.env.PORT}`);
// 		});
// 	} catch (error) {
// 		console.error("ERROR : ", error);
// 		throw error;
// 	}
// })();

import dotenv from "dotenv";
import connectDB from "./db/index.js";
import { app } from "./app.js";

dotenv.config({
	path: "./env",
});

connectDB()
	.then(() => {
		app.on("errror", (error) => {
			console.log(error);
		});
		app.listen(process.env.PORT, () => {
			console.log(`app listening on port ${process.env.PORT}`);
		});
	})
	.catch((error) => {
		console.log(error);
		process.exit(1);
	});
