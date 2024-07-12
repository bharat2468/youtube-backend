import { ApiError } from "../utils/ApiError.js";
import { ZodError } from "zod";

// Middleware for validation
const validate = (schema) => {
	return (req, res, next) => {
		try {
			schema.parse(req.body);
			next();
		} catch (error) {
			if (error instanceof ZodError) {
				// Format errors to be more user-friendly
				const formattedErrors = error.errors.map((err) => ({
					field: err.path[0],
					message: err.message,
				}));
				console.log(formattedErrors);

				return res.status(400).json(
					new ApiError(400, "data validation failed", formattedErrors)
				);
			} else {
				next(error);
			}
		}
	};
};

export { validate };
