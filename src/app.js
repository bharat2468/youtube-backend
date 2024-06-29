import cookieParser from "cookie-parser";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();

const corsOptions = {
	origin: process.env.ALLOWED_ORIGINS,
	credentials: true,
};
app.use(cors(corsOptions));
app.use(cookieParser());

app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));

export { app };
