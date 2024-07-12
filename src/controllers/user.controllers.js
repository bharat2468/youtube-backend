import { asyncHandler } from "../utils/asyncHandler.js";
import { validationResult } from "express-validator";
import { User } from "../models/user.models.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import {
	deleteFromCloudinary,
	uploadOnCloudinary,
} from "../utils/cloudinary.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshToken = async (id) => {
	try {
		const user = await User.findById(id);
		const accessToken = await user.generateAccessToken();
		const refreshToken = await user.generateRefreshToken();

		user.refreshToken = refreshToken;
		await user.save({ validateBeforeSave: false });

		return { accessToken, refreshToken };
	} catch (error) {
		throw new ApiError(
			500,
			"Something went wrong while generating Access and Refresh tokens"
		);
	}
};

const registerUser = asyncHandler(async (req, res) => {
	// 1. get data from the request
	// 2. validate the text data
	// 3. validate the image data
	// 4. check for existing user using username and email
	// 5. upload images on cloud and check for the upload
	// 6. create new document on the database
	// 7. check for the created user
	// 8. return the data by removing password and image

	// 1. get data from the request
	const { username, email, password, fullName } = req.body;

	// 2. validate the text data
	// const errors = validationResult(req);
	// if (!errors.isEmpty()) {
	// 	return res.status(400).json({ errors: errors.array() });
	// }

	// 3. validate the image data
	if (Object.keys(req.files).length === 0) {
		throw new ApiError(400, "Avatar file is required");
	}

	const avatarLocalPath = req.files?.avatar?.[0]?.path;
	const coverImageLocalPath = req.files?.coverImage?.[0]?.path;

	if (!avatarLocalPath) {
		throw new ApiError(400, "Avatar file is required");
	}

	// 4. check for existing user using username and email
	// !use await
	const existingUser = await User.findOne({
		$or: [{ username }, { email }],
	});

	if (existingUser) {
		throw new ApiError(409, "User with email or username already exists");
	}

	// 5. upload images on cloud and check for the upload
	// !use await
	const avatar = await uploadOnCloudinary(avatarLocalPath);
	const coverImage = coverImageLocalPath
		? await uploadOnCloudinary(coverImageLocalPath)
		: null;

	if (!avatar || (coverImageLocalPath && !coverImage)) {
		throw new ApiError(500, "Unable to upload images on cloudinary");
	}

	// 6. create new document on the database
	const user = await User.create({
		fullName,
		avatar: avatar.url,
		coverImage: coverImage?.url || "",
		email,
		password,
		username: username.toLowerCase(),
	});

	// 7. check for the created user
	const createdUser = await User.findById(user._id).select(
		"-password -refreshToken"
	);

	if (!createdUser) {
		throw new ApiError(
			500,
			"Something went wrong while registering the user"
		);
	}

	// 8. return the data by removing password and image
	return res
		.status(201)
		.json(
			new ApiResponse(201, createdUser, "User registered Successfully")
		);
});

const loginUser = asyncHandler(async (req, res) => {
	// 1. take the data from the user
	// 2. validate the data -> error
	// 3. check for the user in the database using email/username -> error
	// 4. if found check password -> error
	// 5. generate access and refresh token
	// 6. return through cookies

	// const errors = validationResult(req);
	// if (!errors.isEmpty()) {
	// 	return res.status(400).json({ errors: errors.array() });
	// }

	if (!username && !email) {
		throw new ApiError(
			400,
			"At least one of username or email must be provided"
		);
	}

	const { username, email, password } = req.body;

	const user = await User.findOne({
		$or: [{ username }, { email }],
	});

	if (!user) {
		throw new ApiError(400, "Invalid username or email");
	}

	const passwordCorrect = await user.isPasswordCorrect(password);

	if (!passwordCorrect) {
		throw new ApiError(400, "Invalid password");
	}

	const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
		user._id
	);

	const options = {
		httpOnly: true,
		secure: true,
	};

	delete user.password;
	delete user.refreshToken;

	return res
		.status(200)
		.cookie("accessToken", accessToken, options)
		.cookie("refreshToken", refreshToken, options)
		.json(
			new ApiResponse(
				200,
				{
					user: user,
					accessToken,
					refreshToken,
				},
				"user logged in successfully"
			)
		);
});

const logoutUser = asyncHandler(async (req, res) => {
	const user = await User.findByIdAndUpdate(
		req.user._id,
		{
			$set: {
				refreshToken: null, // Use null instead of undefined
			},
		},
		{
			new: true,
		}
	);

	if (!user) {
		throw new ApiError(400, "Failed to update user refreshToken");
	}

	const options = {
		httpOnly: true,
		secure: true,
	};

	return res
		.status(200)
		.clearCookie("accessToken", options)
		.clearCookie("refreshToken", options)
		.json(new ApiResponse(200, {}, "User logged out successfully"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
	// check for refresh token in req -> error
	// verify using jwt and decode
	// find user from the db using id
	// verify if same
	// generate access token in cooken as well as body

	const incomingRefreshToken =
		req.cookies.refreshToken || req.body.refreshToken;

	if (!incomingRefreshToken) {
		throw new ApiError(
			401,
			"Unauthorized request - refresh token required"
		);
	}

	try {
		const decodedToken = jwt.verify(
			incomingRefreshToken,
			process.env.REFRESH_TOKEN_SECRET
		);

		if (!decodedToken) {
			throw new ApiError(401, "Invalid refresh token");
		}

		const user = await User.findById(decodedToken._id);

		if (!user) {
			throw new ApiError(401, "User does not exist");
		}

		if (incomingRefreshToken !== user.refreshToken) {
			throw new ApiError(401, "Invalid refresh token");
		}

		const { accessToken, refreshToken } =
			await generateAccessAndRefreshToken(user._id);

		const options = {
			httpOnly: true,
			secure: true,
		};

		res.status(200)
			.cookie("accessToken", accessToken, options)
			.cookie("refreshToken", refreshToken, options)
			.json(
				new ApiResponse(
					200,
					{
						accessToken,
						refreshToken,
					},
					"new tokens generated successfully"
				)
			);
	} catch (error) {
		throw new ApiError(401, error?.message || "Invalid refresh token");
	}
});

const changeExistingPassword = asyncHandler(async (req, res) => {
	// verify jwt token
	// validate password
	// get existing and new password
	// get user
	// verify password
	// set new password
	// const errors = validationResult(req);
	// if (!errors.isEmpty()) {
	// 	return res.status(400).json({ errors: errors.array() });
	// }

	const { oldPassword, newPassword } = req.body;

	if (oldPassword === newPassword) {
		throw new ApiError(400, "new password and old password cannot be same");
	}

	const user = await User.findById(req.user._id);

	const correctPassword = await user.isPasswordCorrect(oldPassword);

	if (!correctPassword) {
		throw new ApiError(400, "Invalid password");
	}

	// !the pre hook of mongoose will not be triggered with find and update method
	user.password = newPassword;
	await user.save();

	res.status(200).json(
		new ApiResponse(200, {}, "password changed successfully")
	);
});

const updateUserFields = asyncHandler(async (req, res) => {
	const { fullName, email } = req.body;

	// Validate input
	// const errors = validationResult(req);
	// if (!errors.isEmpty()) {
	// 	return res.status(400).json({ errors: errors.array() });
	// }

	// Ensure at least one field is provided
	if (!fullName && !email) {
		throw new ApiError(
			400,
			"At least one of fullName or email must be provided"
		);
	}

	// Find and update user
	const user = await User.findByIdAndUpdate(
		req.user._id,
		{
			...(fullName && { fullName }),
			...(email && { email }),
		},
		{
			new: true,
		}
	).select("-password -refreshToken");

	if (!user) {
		throw new ApiError(404, "User not found");
	}

	// Return updated user
	return res
		.status(200)
		.json(new ApiResponse(200, user, "User updated successfully"));
});

const getUser = asyncHandler(async (req, res) => {
	return res.status(200).json(
		new ApiResponse(
			200,
			{
				user: req.user,
			},
			"current user returned successfully"
		)
	);
});

const updateAvatar = asyncHandler(async (req, res) => {
	// get new avatar file -> error
	// upload new on cloudinary -> error
	// update in the database
	// delete prev from db

	const newAvatarLocalPath = req?.file?.path;

	if (!newAvatarLocalPath) {
		throw new ApiError(400, "new Avatar file required");
	}

	const newAvatarCloudObject = await uploadOnCloudinary(newAvatarLocalPath);

	const newAvatarCloudUrl = newAvatarCloudObject?.url;
	// const newAvatarPublicId = newAvatarCloudObject?.public_id;

	if (!newAvatarCloudUrl) {
		throw new ApiError(
			500,
			"unable to upload new avatar file on cloudinary"
		);
	}

	const user = await User.findByIdAndUpdate(req.user._id, {
		$set: {
			avatar: newAvatarCloudUrl,
		},
	});

	const oldAvatarUrl = user.avatar;
	console.log(oldAvatarUrl);
	const publicId = oldAvatarUrl
		? oldAvatarUrl.split("/").slice(-1)[0].split(".")[0]
		: null;

	await deleteFromCloudinary(publicId);

	user.avatar = newAvatarCloudUrl;

	return res
		.status(200)
		.json(new ApiResponse(200, user, "avatar changed successfully"));
});


const updateCoverImage = asyncHandler(async (req, res) => {
	// get new avatar file -> error
	// upload new on cloudinary -> error
	// update in the database
	// delete prev from db

	const newCoverImageLocalPath = req?.file?.path;

	if (!newCoverImageLocalPath) {
		throw new ApiError(400, "new Cover Image file required");
	}

	const newCoverImageCloudObject = await uploadOnCloudinary(newCoverImageLocalPath);

	const newCoverImageCloudUrl = newCoverImageCloudObject?.url;
	// const newAvatarPublicId = newAvatarCloudObject?.public_id;

	if (!newCoverImageCloudUrl) {
		throw new ApiError(
			500,
			"unable to upload new cover image file on cloudinary"
		);
	}

	const user = await User.findByIdAndUpdate(req.user._id, {
		$set: {
			coverImage: newCoverImageCloudUrl,
		},
	});

	const oldCoverImageUrl = user.coverImage;
	console.log(oldCoverImageUrl);
	const publicId = oldCoverImageUrl
		? oldCoverImageUrl.split("/").slice(-1)[0].split(".")[0]
		: null;

	await deleteFromCloudinary(publicId);

	user.coverImage = newCoverImageCloudUrl;

	return res
		.status(200)
		.json(new ApiResponse(200, user, "Cover Image changed successfully"));
});

export {
	registerUser,
	loginUser,
	logoutUser,
	refreshAccessToken,
	changeExistingPassword,
	updateUserFields,
	getUser,
	updateAvatar,
	updateCoverImage
};
