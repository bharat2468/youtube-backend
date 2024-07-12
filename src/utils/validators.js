import { z } from "zod";

// Complex validation functions
const isEmail = z
	.string()
	.min(1, "Email is required")
	.email("Invalid email format")
	.transform((email) => email.trim().toLowerCase());

const isUsername = z
	.string()
	.min(3, "Username must be at least 3 characters")
	.max(20, "Username must be at most 20 characters")
	.regex(
		/^[a-zA-Z0-9_]+$/,
		"Username can only contain letters, numbers, and underscores"
	);

const isFullName = z
	.string()
	.min(1, "Full name is required")
	.regex(/^[a-zA-Z\s]+$/, "Full name can only contain letters and spaces");

const passwordComplexity = z
	.string()
	.min(8, "Password must be at least 8 characters long")
	.regex(/\d/, "Password must contain at least one number")
	.regex(/[a-z]/, "Password must contain at least one lowercase letter")
	.regex(/[A-Z]/, "Password must contain at least one uppercase letter")
	.regex(
		/[!@#$%^&*(),.?":{}|<>]/,
		"Password must contain at least one special character"
	);

// !Schema definitions
const registrationSchema = z.object({
	username: isUsername,
	email: isEmail,
	password: passwordComplexity,
	fullName: isFullName,
});

const loginSchema = z.object({
	username: isUsername.optional(),
	email: isEmail.optional(),
	password: z.string().min(1, "Password is required"),
});

const changePasswordSchema = z.object({
	oldPassword: z.string().min(1, "Old password is required"),
	newPassword: passwordComplexity,
});

const updateUserSchema = z.object({
	fullName: isFullName.optional(),
	email: isEmail.optional(),
});

// !Export schemas
export {
	registrationSchema,
	loginSchema,
	changePasswordSchema,
	updateUserSchema,
};
