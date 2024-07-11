import { Router } from "express";
import {
	loginUser,
	logoutUser,
	refreshAccessToken,
	registerUser,
} from "../controllers/user.controllers.js";
import { upload } from "../middlewares/multer.middleware.js";
import { validateRegisterFields } from "../utils/validators.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

router.route("/register").post(
	upload.fields([
		{
			name: "avatar",
			maxCount: 1,
		},
		{
			name: "coverImage",
			maxCount: 1,
		},
	]),
	validateRegisterFields,
	registerUser
);

router.route("/login").post(loginUser);

router.route("/logout").post(verifyJWT, logoutUser);

router.route("/generateToken").post(refreshAccessToken);

export default router;
