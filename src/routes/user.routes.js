import { Router } from "express";
import {
	changeExistingPassword,
	getUser,
	loginUser,
	logoutUser,
	refreshAccessToken,
	registerUser,
	updateUserFields,
	updateAvatar,
	updateCoverImage
} from "../controllers/user.controllers.js";
import { upload } from "../middlewares/multer.middleware.js";
import {
	registrationSchema,
	loginSchema,
	updateUserSchema,
	changePasswordSchema,
} from "../utils/validators.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";
import { validate } from "../middlewares/validate.middleware.js";

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
	validate(registrationSchema),
	registerUser
);

router.route("/login").post(validate(loginSchema), loginUser);

router.route("/logout").post(verifyJWT, logoutUser);

router.route("/generateToken").post(refreshAccessToken);

router
	.route("/change-password")
	.post(verifyJWT, validate(changePasswordSchema), changeExistingPassword);

router.route("/get-user").get(verifyJWT, getUser);

router
	.route("/update-user-details")
	.post(verifyJWT, validate(updateUserSchema), updateUserFields);

router.route("/update-avatar").post(verifyJWT,upload.single("avatar"),updateAvatar);

router.route("/update-cover-image").post(verifyJWT,upload.single("coverImage"),updateCoverImage);

export default router;
