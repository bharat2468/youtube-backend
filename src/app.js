import cookieParser from "cookie-parser";
import express from "express";
import cors from "cors";


const app = express();

//? CORS config
const corsOptions = {
	origin: process.env.ALLOWED_ORIGINS,
	credentials: true,
};
app.use(cors(corsOptions));

//? cookie parser config to read cookies 
app.use(cookieParser());

//? config for data recieved in the requests 
app.use(express.json({ limit: "16 kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));

// !routes import 
import userRoutes from "./routes/user.routes.js"


// !routes declare 
app.use("/api/v1/users",userRoutes);


export { app };
