const allowedOrigins = [
  "http://localhost:5174",
  "http://localhost:5173",
  "https://inzynierka-user.vercel.app",
  "https://inzynierka-admin.vercel.app",
  "https://inzynierka-admin-p7h6vq649-weronikawros-projects.vercel.app",
];

const corsOptions = {
  origin: function (origin, callback) {
    if (
      !origin ||
      allowedOrigins.includes(origin) ||
      origin.endsWith(".vercel.app")
    ) {
      callback(null, true);
    } else {
      console.log("Zablokowany Origin przez CORS:", origin);
      callback(new Error("Brak dostępu CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Accept"],
  credentials: true,
  optionsSuccessStatus: 200,
};

module.exports = { corsOptions };
