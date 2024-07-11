import { asyncHandler } from "../utils/asyncHandler.js";
import { validationResult } from "express-validator";
import { User } from "../models/user.models.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
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
	const errors = validationResult(req);
	if (!errors.isEmpty()) {
		return res.status(400).json({ errors: errors.array() });
	}

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

	const errors = validationResult(req);
	if (!errors.isEmpty()) {
		return res.status(400).json({ errors: errors.array() });
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
                refreshToken: null,  // Use null instead of undefined
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


export { registerUser, loginUser, logoutUser, refreshAccessToken };
