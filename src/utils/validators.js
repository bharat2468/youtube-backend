import { body } from "express-validator";

// Validators for registration
const usernameRegistrationValidation = body("username")
	.notEmpty()
	.withMessage("Username is required")
	.bail()
	.isLength({ min: 3, max: 20 })
	.withMessage("Username must be between 3 and 20 characters")
	.matches(/^[a-zA-Z0-9_]+$/)
	.withMessage("Username can only contain letters, numbers, and underscores");

const emailRegistrationValidation = body("email")
	.notEmpty()
	.withMessage("Email is required")
	.bail()
	.isEmail()
	.withMessage("Invalid email format")
	.normalizeEmail();

const passwordRegistrationValidation = body("password")
	.notEmpty()
	.withMessage("Password is required")
	.bail()
	.isLength({ min: 8 })
	.withMessage("Password must be at least 8 characters long")
	.matches(/\d/)
	.withMessage("Password must contain at least one number")
	.matches(/[a-z]/)
	.withMessage("Password must contain at least one lowercase letter")
	.matches(/[A-Z]/)
	.withMessage("Password must contain at least one uppercase letter")
	.matches(/[!@#$%^&*(),.?":{}|<>]/)
	.withMessage("Password must contain at least one special character");

const fullnameRegistrationValidation = body("fullName")
	.notEmpty()
	.withMessage("Full name is required")
	.bail()
	.matches(/^[a-zA-Z\s]+$/)
	.withMessage("Full name can only contain letters and spaces");

const validateRegisterFields = [
	usernameRegistrationValidation,
	emailRegistrationValidation,
	passwordRegistrationValidation,
	fullnameRegistrationValidation,
];

// Validators for login
const usernameLoginValidation = body("username")
	.if(body("email").isEmpty())
	.notEmpty()
	.withMessage("Username is required")
	.bail()
	.isLength({ min: 3, max: 20 })
	.withMessage("Invalid username")
	.matches(/^[a-zA-Z0-9_]+$/)
	.withMessage("Invalid username");

const emailLoginValidation = body("email")
	.if(body("username").isEmpty())
	.notEmpty()
	.withMessage("Email is required")
	.bail()
	.isEmail()
	.withMessage("Invalid email")
	.normalizeEmail();

const passwordLoginValidation = body("password")
	.notEmpty()
	.withMessage("Password is required");

const validateLoginFields = [
	usernameLoginValidation,
	emailLoginValidation,
	passwordLoginValidation,
];

export { validateRegisterFields, validateLoginFields };
