import multer from "multer";

const errorHandler = (err, req, res, next) => {
	if (err instanceof multer.MulterError) {
		// Handle Multer-specific errors with detailed messages
		switch (err.code) {
			case "LIMIT_FILE_SIZE":
				return res
					.status(400)
					.send({ error: "File size exceeds limit (5MB)." });
			case "LIMIT_FILE_COUNT":
				return res
					.status(400)
					.send({ error: "File count exceeds limit." });
			case "LIMIT_FIELD_KEY":
				return res.status(400).send({ error: "Field name too long." });
			case "LIMIT_FIELD_VALUE":
				return res.status(400).send({ error: "Field value too long." });
			case "LIMIT_UNEXPECTED_FILE":
				return res
					.status(400)
					.send({ error: "Unexpected file field." });
			default:
				return res.status(400).send({ error: err.message });
		}
	} else if (err.message === "Only .png and .jpg files are allowed") {
		// Handle custom file type validation error
		return res.status(400).send({ error: err.message });
	}
	// General error handling
	res.status(500).send({ error: "An unexpected error occurred." });
};

export {errorHandler};
