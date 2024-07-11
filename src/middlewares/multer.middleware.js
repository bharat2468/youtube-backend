import multer from "multer";

// Configure Multer storage
const storage = multer.diskStorage({
	destination: (req, file, cb) => {
		cb(null, "./public/temp"); // Temporary storage directory
	},
	filename: (req, file, cb) => {
		cb(null, file.originalname); // Use the original name of the file
	},
});

// Configure Multer for file uploads
const upload = multer({
	storage: storage,
	fileFilter: (req, file, cb) => {
		// Validate file types
		if (file.mimetype === "image/png" || file.mimetype === "image/jpeg") {
			cb(null, true);
		} else {
			cb(new Error("Only .png and .jpg files are allowed"), false);
		}
	},
	limits: {
		fileSize: 1024 * 1024 * 5, // 5MB file size limit
	},
});

export {upload};