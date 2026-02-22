require("dotenv").config();
const express = require("express");
const { MongoClient, ObjectId } = require("mongodb");
const nodemailer = require("nodemailer");
const cors = require("cors");
const net = require("net");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const { corsOptions } = require("./config");
const { getResetEmailTemplate } = require("./email_templates");
const {
  authenticateToken,
  optionalAuthenticateToken,
  requireAdmin,
  JWT_SECRET,
} = require("./middleware");

const app = express();

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

app.use(cors(corsOptions));

const ADMIN_REGISTRATION_CODE = process.env.ADMIN_REGISTRATION_CODE;
const MONGO_URL = process.env.MONGO_URL;
const DB_NAME = "dietApp";

const transporter = nodemailer.createTransport({
  host: "smtp-relay.brevo.com",
  port: 2525,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

let db;

function checkPort(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(port, () => {
      server.once("close", () => resolve(true));
      server.close();
    });
    server.on("error", () => resolve(false));
  });
}

async function findAvailablePort(startPort = 3001) {
  let port = startPort;
  while (!(await checkPort(port))) {
    port++;
  }
  return port;
}

// ------------------------------
//      Połączenie z bazą
// ------------------------------

MongoClient.connect(MONGO_URL)
  .then((client) => {
    console.log("Połączono z MongoDB");
    db = client.db(DB_NAME);
  })
  .catch((error) => console.error("Błąd połączenia z MongoDB:", error));

// ------------------------------
//         Autoryzacja
// ------------------------------

//user

app.post("/api/auth/register-admin", async (req, res) => {
  try {
    const { firstName, lastName, email, password, adminCode } = req.body;
    if (adminCode !== ADMIN_REGISTRATION_CODE)
      return res.status(403).json({ error: "Błędny kod" });

    const existing = await db
      .collection("users")
      .findOne({ email: email.toLowerCase() });
    if (existing)
      return res.status(400).json({ error: "Użytkownik już istnieje" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = {
      firstName,
      lastName,
      email: email.toLowerCase(),
      password: hashedPassword,
      role: "admin",
      profileComplete: true,
      createdAt: new Date(),
    };
    const result = await db.collection("users").insertOne(newAdmin);
    const token = jwt.sign(
      { userId: result.insertedId, role: "admin", email: newAdmin.email },
      JWT_SECRET,
      { expiresIn: "1h" },
    );
    res.status(201).json({
      token,
      user: { ...newAdmin, _id: result.insertedId, password: undefined },
    });
  } catch (e) {
    res.status(500).json({ error: "Błąd serwera" });
  }
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const { userName, firstName, lastName, email, password } = req.body;
    const existing = await db
      .collection("users")
      .findOne({ email: email.toLowerCase() });
    if (existing) return res.status(400).json({ error: "Email zajęty" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = {
      userName,
      firstName,
      lastName,
      email: email.toLowerCase(),
      password: hashedPassword,
      role: "user",
      createdAt: new Date(),
      bmiData: null,
      profileComplete: false,
    };
    const result = await db.collection("users").insertOne(user);
    const token = jwt.sign(
      { userId: result.insertedId, role: "user", email: user.email },
      JWT_SECRET,
      { expiresIn: "24h" },
    );
    res.status(201).json({
      token,
      user: { ...user, _id: result.insertedId, password: undefined },
    });
  } catch (e) {
    res.status(500).json({ error: "Błąd serwera" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await db
      .collection("users")
      .findOne({ email: email.toLowerCase() });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: "Błąd logowania" });
    const token = jwt.sign(
      { userId: user._id, role: user.role, email: user.email },
      JWT_SECRET,
      { expiresIn: "24h" },
    );
    res.json({ token, user: { ...user, password: undefined } });
  } catch (e) {
    res.status(500).json({ error: "Błąd serwera" });
  }
});

// admin

app.post("/api/auth/login-admin", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await db
      .collection("users")
      .findOne({ email: email.toLowerCase() });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: "Błędne dane" });
    if (user.role !== "admin")
      return res
        .status(403)
        .json({ error: "Nie jesteś administratorem! Dostęp zabroniony." });
    const token = jwt.sign(
      { userId: user._id, role: "admin", email: user.email },
      JWT_SECRET,
      { expiresIn: "24h" },
    );
    res.json({ token, user: { ...user, password: undefined } });
  } catch (e) {
    res.status(500).json({ error: "Błąd serwera" });
  }
});

// ------------------------------
//         Reset hasła
// ------------------------------

// user

app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await db
      .collection("users")
      .findOne({ email: email.toLowerCase() });

    if (!user) {
      return res.json({
        message: "Jeśli konto istnieje, link został wysłany.",
      });
    }

    const token = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 86400000);

    await db
      .collection("users")
      .updateOne(
        { _id: user._id },
        { $set: { resetPasswordToken: token, resetPasswordExpires: expires } },
      );

    const frontendUrl =
      process.env.FRONTEND_USER_URL || "http://localhost:5174";
    const resetLink = `${frontendUrl}/?page=reset-password&token=${token}`;

    await transporter.sendMail({
      from: '"Diet App" <weronika.wiktoria.wroblewska@gmail.com>',
      to: email,
      subject: "Reset hasła - Aplikacja do zarządzania dietą",
      html: getResetEmailTemplate(resetLink),
    });

    res.json({ message: "Link wysłany." });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Błąd wysyłania" });
  }
});

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body;
    const user = await db.collection("users").findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: new Date() },
    });
    if (!user) return res.status(400).json({ error: "Token wygasł" });
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.collection("users").updateOne(
      { _id: user._id },
      {
        $set: { password: hashedPassword },
        $unset: { resetPasswordToken: 1, resetPasswordExpires: 1 },
      },
    );
    res.json({ message: "Hasło zmienione." });
  } catch (e) {
    res.status(500).json({ error: "Błąd" });
  }
});

app.get("/api/auth/verify", authenticateToken, async (req, res) => {
  try {
    const user = await db
      .collection("users")
      .findOne({ _id: new ObjectId(req.user.userId) });
    if (!user) return res.status(404).json({ error: "Brak użytkownika" });
    const { password, ...safeUser } = user;
    res.json({ user: safeUser });
  } catch (e) {
    res.status(500).json({ error: "Błąd" });
  }
});

app.post("/api/auth/change-password", authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const user = await db
      .collection("users")
      .findOne({ _id: new ObjectId(req.user.userId) });
    if (!user) {
      return res.status(404).json({ message: "Nie znaleziono użytkownika" });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res
        .status(400)
        .json({ message: "Obecne hasło jest nieprawidłowe" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db
      .collection("users")
      .updateOne(
        { _id: new ObjectId(req.user.userId) },
        { $set: { password: hashedPassword } },
      );

    res.json({ message: "Hasło zostało pomyślnie zmienione." });
  } catch (error) {
    console.error("Błąd zmiany hasła:", error);
    res.status(500).json({ message: "Błąd serwera podczas zmiany hasła" });
  }
});

// ------------------------------
//         bmi i profil
// ------------------------------

app.post("/api/user/bmi-data", authenticateToken, async (req, res) => {
  try {
    const {
      age,
      height,
      weight,
      gender,
      activityLevel,
      firstName,
      lastName,
      image,
    } = req.body;

    const numAge = parseInt(age);
    const numHeight = parseFloat(height);
    const numWeight = parseFloat(weight);

    const heightInMeters = numHeight / 100;
    const bmi = numWeight / (heightInMeters * heightInMeters);

    let bmr =
      gender === "male"
        ? 10 * numWeight + 6.25 * numHeight - 5 * numAge + 5
        : 10 * numWeight + 6.25 * numHeight - 5 * numAge - 161;

    const multi = {
      sedentary: 1.2,
      lightly_active: 1.375,
      moderately_active: 1.55,
      very_active: 1.725,
      extremely_active: 1.9,
    };
    const tdee = bmr * multi[activityLevel];

    let bmiCategory = "normal";
    if (bmi < 18.5) bmiCategory = "underweight";
    else if (bmi < 25) bmiCategory = "normal";
    else if (bmi < 30) bmiCategory = "overweight";
    else bmiCategory = "obese";

    const currentUser = await db
      .collection("users")
      .findOne({ _id: new ObjectId(req.user.userId) });

    const bmiData = {
      age: numAge,
      height: numHeight,
      weight: numWeight,
      gender: gender,
      activityLevel: activityLevel,
      bmi: Math.round(bmi * 10) / 10,
      bmiCategory: bmiCategory,
      bmr: Math.round(bmr),
      tdee: Math.round(tdee),
      protein: Math.round(numWeight * 1.8),
      fat: Math.round(numWeight * 1.0),
      carbs: Math.round((tdee - (numWeight * 1.8 * 4 + numWeight * 1 * 9)) / 4),
      updatedAt: new Date(),
    };

    if (
      currentUser &&
      currentUser.bmiData &&
      currentUser.bmiData.initialWeight
    ) {
      bmiData.initialWeight = currentUser.bmiData.initialWeight;
    } else {
      bmiData.initialWeight = numWeight;
    }

    const updateFields = {
      bmiData,
      profileComplete: true,
      updatedAt: new Date(),
    };

    if (firstName && firstName.trim() !== "")
      updateFields.firstName = firstName;
    if (lastName && lastName.trim() !== "") updateFields.lastName = lastName;
    if (image && image.trim() !== "") updateFields.image = image;

    await db
      .collection("users")
      .updateOne(
        { _id: new ObjectId(req.user.userId) },
        { $set: updateFields },
      );

    res.json({ message: "Zapisano", bmiData });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Błąd BMI" });
  }
});

// ------------------------------
//           Produkty
// ------------------------------

app.get("/api/products", authenticateToken, async (req, res) => {
  try {
    const adminP = await db
      .collection("products")
      .find({ isSystem: true })
      .toArray();
    let userP =
      req.user.role !== "admin"
        ? await db
            .collection("products")
            .find({ userId: req.user.userId })
            .toArray()
        : [];
    res.json(
      [...adminP, ...userP].sort((a, b) => a.name.localeCompare(b.name)),
    );
  } catch (e) {
    res.status(500).json({ error: "Błąd" });
  }
});

app.post("/api/products", authenticateToken, async (req, res) => {
  try {
    const product = {
      ...req.body,
      calories: parseFloat(req.body.calories) || 0,
      protein: parseFloat(req.body.protein) || 0,
      carbs: parseFloat(req.body.carbs) || 0,
      fat: parseFloat(req.body.fat) || 0,
      userId: req.user.userId,
      isSystem: req.user.role === "admin",
      createdAt: new Date(),
    };
    const result = await db.collection("products").insertOne(product);
    res.status(201).json({ ...product, _id: result.insertedId });
  } catch (e) {
    res.status(500).json({ error: "Błąd" });
  }
});

// ------------------------------
//          Przepisy
// ------------------------------

async function processNewIngredients(
  ingredients,
  userId,
  dbInstance,
  userRole,
) {
  if (!ingredients || !Array.isArray(ingredients)) return [];

  return await Promise.all(
    ingredients.map(async (ing) => {
      if (ing.productId) return ing;

      if (!ing.name || ing.name.trim() === "") return ing;

      try {
        const amount = parseFloat(ing.amount) || 100;
        const ratio = 100 / amount;

        const newProd = {
          name: ing.name,
          category: "other",
          calories: parseFloat(ing.calories * ratio) || 0,
          protein: parseFloat(ing.protein * ratio) || 0,
          carbs: parseFloat(ing.carbs * ratio) || 0,
          fat: parseFloat(ing.fat * ratio) || 0,
          userId,
          isSystem: userRole === "admin",
          createdAt: new Date(),
        };

        const res = await dbInstance.collection("products").insertOne(newProd);
        return { ...ing, productId: res.insertedId };
      } catch (err) {
        console.error("Błąd przy dodawaniu produktu ze składnika:", err);
        return ing;
      }
    }),
  );
}

app.get("/api/recipes", optionalAuthenticateToken, async (req, res) => {
  try {
    const query = { $or: [{ isGlobal: true }] };
    if (req.user && req.user.role !== "admin") {
      query.$or.push({ userId: req.user.userId });
    }
    const recipes = await db
      .collection("recipes")
      .find(query)
      .sort({ createdAt: -1 })
      .toArray();
    res.json(recipes);
  } catch (e) {
    res.status(500).json({ error: "Błąd" });
  }
});

app.post("/api/recipes", authenticateToken, async (req, res) => {
  try {
    const processed = await processNewIngredients(
      req.body.ingredients,
      req.user.userId,
      db,
      req.user.role,
    );
    const recipe = {
      ...req.body,
      ingredients: processed,
      userId: req.user.userId,
      authorRole: req.user.role,
      isGlobal: req.user.role === "admin",
      createdAt: new Date(),
    };
    const result = await db.collection("recipes").insertOne(recipe);
    res.status(201).json({ ...recipe, _id: result.insertedId });
  } catch (e) {
    res.status(500).json({ error: "Błąd" });
  }
});

app.delete("/api/recipes/:id", authenticateToken, async (req, res) => {
  try {
    let cleanId = req.params.id;
    if (cleanId.includes(":")) cleanId = cleanId.split(":")[0];

    let queryId;
    if (ObjectId.isValid(cleanId)) {
      queryId = new ObjectId(cleanId);
    } else {
      queryId = !isNaN(cleanId) ? parseInt(cleanId) : cleanId;
    }

    const query =
      req.user.role === "admin"
        ? { _id: queryId }
        : { _id: queryId, userId: req.user.userId };

    const result = await db.collection("recipes").deleteOne(query);

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ error: "Nie znaleziono przepisu lub brak uprawnień" });
    }

    res.json({ message: "Usunięto" });
  } catch (e) {
    console.error("Błąd usuwania przepisu:", e);
    res.status(500).json({ error: "Błąd serwera podczas usuwania" });
  }
});

// ------------------------------
//       Admin dashboard
// ------------------------------

app.get(
  "/api/admin/stats",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const usersCount = await db
        .collection("users")
        .countDocuments({ role: "user" });
      const recipesCount = await db
        .collection("recipes")
        .countDocuments({ isGlobal: true });
      const articlesCount = await db.collection("articles").countDocuments();

      res.json({
        users: usersCount,
        recipes: recipesCount,
        articles: articlesCount,
      });
    } catch (e) {
      res.status(500).json({ error: "Błąd pobierania statystyk" });
    }
  },
);

app.get(
  "/api/admin/stats/monthly",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const now = new Date();
      const month =
        req.query.month !== undefined
          ? parseInt(req.query.month)
          : now.getMonth();
      const year =
        req.query.year !== undefined
          ? parseInt(req.query.year)
          : now.getFullYear();

      const startDate = new Date(year, month, 1, 0, 0, 0);
      const endDate = new Date(year, month + 1, 0, 23, 59, 59);

      const getDailyData = async (collectionName, filter = {}) => {
        return await db
          .collection(collectionName)
          .aggregate([
            {
              $match: {
                ...filter,
                createdAt: { $gte: startDate, $lte: endDate },
              },
            },
            {
              $group: {
                _id: { $dayOfMonth: "$createdAt" },
                count: { $sum: 1 },
              },
            },
          ])
          .toArray();
      };

      const [uData, rData, aData] = await Promise.all([
        getDailyData("users", { role: "user" }),
        getDailyData("recipes", { isGlobal: true }),
        getDailyData("articles"),
      ]);

      const daysInMonth = endDate.getDate();
      const stats = [];

      for (let d = 1; d <= daysInMonth; d++) {
        const find = (list) => list.find((i) => i._id === d)?.count || 0;

        stats.push({
          day: d,
          label: d.toString(),
          users: find(uData),
          recipes: find(rData),
          articles: find(aData),
        });
      }

      res.json(stats);
    } catch (e) {
      res.status(500).json({ error: "Błąd wykresu" });
    }
  },
);

app.get(
  "/api/admin/dashboard/recent",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const recentArticles = await db
        .collection("articles")
        .find({})
        .sort({ createdAt: -1 })
        .limit(5)
        .toArray();

      const recentRecipes = await db
        .collection("recipes")
        .find({ isGlobal: true })
        .sort({ createdAt: -1 })
        .limit(5)
        .toArray();

      res.json({ articles: recentArticles, recipes: recentRecipes });
    } catch (e) {
      res.status(500).json({ error: "Błąd dashboardu" });
    }
  },
);

// ------------------------------
//      resetowanie hasła
// ------------------------------

//admin

app.post("/api/auth/forgot-password-admin", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await db.collection("users").findOne({
      email: email.toLowerCase(),
      role: "admin",
    });

    if (!user) {
      return res.json({ message: "Link wysłany (jeśli konto istnieje)." });
    }

    const token = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 86400000);

    await db
      .collection("users")
      .updateOne(
        { _id: user._id },
        { $set: { resetPasswordToken: token, resetPasswordExpires: expires } },
      );

    const frontendUrl =
      process.env.FRONTEND_ADMIN_URL || "http://localhost:5173";
    const resetLink = `${frontendUrl}/?page=reset-password&token=${token}`;

    await transporter.sendMail({
      from: '"Admin Panel" <weronika.wiktoria.wroblewska@gmail.com>',
      to: email,
      subject:
        "Reset hasła (Panel Administratora) - Aplikacja do zarządzania dietą",
      html: getResetEmailTemplate(resetLink),
    });

    res.json({ message: "Link wysłany." });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Błąd wysyłania emaila" });
  }
});

app.post("/api/auth/reset-password-admin", async (req, res) => {
  try {
    const { token, password } = req.body;

    const user = await db.collection("users").findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: new Date() },
      role: "admin",
    });

    if (!user) {
      return res
        .status(400)
        .json({ error: "Token wygasł lub jest nieprawidłowy." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.collection("users").updateOne(
      { _id: user._id },
      {
        $set: { password: hashedPassword },
        $unset: { resetPasswordToken: 1, resetPasswordExpires: 1 },
      },
    );

    res.json({ message: "Hasło zostało zmienione." });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Błąd zmiany hasła" });
  }
});

// ------------------------------
//            Artykuły
// ------------------------------

app.get("/api/articles", async (req, res) => {
  try {
    const art = await db.collection("articles").find().toArray();
    res.json(art);
  } catch (e) {
    res.status(500).json({ error: "Błąd" });
  }
});

app.post("/api/articles", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const article = {
      ...req.body,
      userId: req.user.userId,
      createdAt: new Date(),
    };
    const resl = await db.collection("articles").insertOne(article);
    res.status(201).json({ ...article, _id: resl.insertedId });
  } catch (e) {
    res.status(500).json({ error: "Błąd" });
  }
});

// ------------------------------
//            Dziennik
// ------------------------------

app.get("/api/diary/:date", authenticateToken, async (req, res) => {
  try {
    const items = await db
      .collection("diary")
      .find({ date: req.params.date, userId: req.user.userId })
      .toArray();
    res.json(items);
  } catch (e) {
    res.status(500).json({ error: "Błąd" });
  }
});

app.post("/api/diary", authenticateToken, async (req, res) => {
  try {
    const item = {
      ...req.body,
      userId: req.user.userId,
      createdAt: new Date(),
    };
    const resl = await db.collection("diary").insertOne(item);
    res.status(201).json({ ...item, _id: resl.insertedId });
  } catch (e) {
    res.status(500).json({ error: "Błąd" });
  }
});

app.put("/api/diary/:id", authenticateToken, async (req, res) => {
  try {
    const { _id, userId, ...updateData } = req.body;
    let cleanId = req.params.id;
    if (cleanId.includes(":")) cleanId = cleanId.split(":")[0];

    const result = await db
      .collection("diary")
      .updateOne(
        { _id: new ObjectId(cleanId), userId: req.user.userId },
        { $set: { ...updateData, updatedAt: new Date() } },
      );

    if (result.matchedCount === 0) {
      return res
        .status(404)
        .json({ error: "Nie znaleziono wpisu lub brak uprawnień" });
    }

    res.json({ message: "Zaktualizowano" });
  } catch (e) {
    console.error("Błąd edycji dziennika:", e);
    res.status(500).json({ error: "Błąd serwera" });
  }
});

app.delete("/api/diary/:id", authenticateToken, async (req, res) => {
  try {
    let cleanId = req.params.id;
    if (cleanId.includes(":")) cleanId = cleanId.split(":")[0];

    const result = await db.collection("diary").deleteOne({
      _id: new ObjectId(cleanId),
      userId: req.user.userId,
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: "Nie znaleziono wpisu" });
    }

    res.json({ message: "Usunięto" });
  } catch (e) {
    console.error("Błąd usuwania z dziennika:", e);
    res.status(500).json({ error: "Błąd serwera" });
  }
});

app.get(
  "/api/admin/users",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const users = await db.collection("users").find().toArray();
      const safeUsers = users.map((u) => {
        const { password, ...rest } = u;
        return rest;
      });
      res.json(safeUsers);
    } catch (e) {
      res.status(500).json({ error: "Błąd pobierania użytkowników" });
    }
  },
);

app.delete("/api/products/:id", authenticateToken, async (req, res) => {
  try {
    const query =
      req.user.role === "admin"
        ? { _id: new ObjectId(req.params.id) }
        : { _id: new ObjectId(req.params.id), userId: req.user.userId };

    const result = await db.collection("products").deleteOne(query);

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ error: "Produkt nie znziony lub brak uprawnień" });
    }

    res.json({ message: "Produkt usunięty" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Błąd serwera przy usuwaniu produktu" });
  }
});

app.delete(
  "/api/articles/:id",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const result = await db.collection("articles").deleteOne({
        _id: new ObjectId(req.params.id),
      });

      if (result.deletedCount === 0) {
        return res.status(404).json({ error: "Artykuł nie znaleziony" });
      }

      res.json({ message: "Artykuł usunięty" });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Błąd serwera przy usuwaniu artykułu" });
    }
  },
);

app.delete(
  "/api/admin/users/:id",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      if (req.params.id === req.user.userId) {
        return res
          .status(400)
          .json({ error: "Nie możesz usunąć własnego konta" });
      }

      const result = await db.collection("users").deleteOne({
        _id: new ObjectId(req.params.id),
      });

      if (result.deletedCount === 0) {
        return res.status(404).json({ error: "Użytkownik nie znaleziony" });
      }

      res.json({ message: "Użytkownik usunięty" });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Błąd serwera przy usuwaniu użytkownika" });
    }
  },
);

app.put(
  "/api/articles/:id",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const { _id, ...updateData } = req.body;

      updateData.updatedAt = new Date();

      const result = await db
        .collection("articles")
        .updateOne({ _id: new ObjectId(req.params.id) }, { $set: updateData });

      res.json({
        message: "Zaktualizowano",
        modifiedCount: result.modifiedCount,
      });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Błąd edycji artykułu" });
    }
  },
);

app.put("/api/products/:id", authenticateToken, async (req, res) => {
  try {
    const { _id, userId, ...updateData } = req.body;

    if (updateData.calories)
      updateData.calories = parseFloat(updateData.calories);
    if (updateData.protein) updateData.protein = parseFloat(updateData.protein);
    if (updateData.carbs) updateData.carbs = parseFloat(updateData.carbs);
    if (updateData.fat) updateData.fat = parseFloat(updateData.fat);

    const query =
      req.user.role === "admin"
        ? { _id: new ObjectId(req.params.id) }
        : { _id: new ObjectId(req.params.id), userId: req.user.userId };

    const result = await db
      .collection("products")
      .updateOne(query, { $set: updateData });

    res.json({
      message: "Zaktualizowano",
      modifiedCount: result.modifiedCount,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Błąd edycji produktu" });
  }
});

app.put("/api/recipes/:id", authenticateToken, async (req, res) => {
  try {
    const { _id, userId, ...updateData } = req.body;
    let paramId = req.params.id;

    if (paramId.includes(":")) paramId = paramId.split(":")[0];

    let query;
    if (ObjectId.isValid(paramId)) {
      query = {
        $or: [{ _id: new ObjectId(paramId) }, { _id: paramId }],
      };
    } else {
      const numId = parseInt(paramId);
      query = {
        $or: [{ _id: isNaN(numId) ? paramId : numId }, { _id: paramId }],
      };
    }

    if (req.user.role !== "admin") {
      query = {
        $and: [query, { userId: req.user.userId }],
      };
    }

    if (updateData.ingredients) {
      updateData.ingredients = await processNewIngredients(
        updateData.ingredients,
        req.user.userId,
        db,
        req.user.role,
      );
    }

    updateData.updatedAt = new Date();

    const result = await db
      .collection("recipes")
      .updateOne(query, { $set: updateData });

    if (result.matchedCount === 0) {
      return res
        .status(404)
        .json({ error: "Przepis nie znaleziony lub brak uprawnień" });
    }

    const updatedRecipe = await db.collection("recipes").findOne(query);

    res.json({ message: "Przepis zaktualizowany", recipe: updatedRecipe });
  } catch (e) {
    console.error("Błąd edycji przepisu:", e);
    res.status(500).json({ error: "Błąd serwera podczas edycji" });
  }
});

app.put(
  "/api/admin/profile",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const { firstName, lastName, image } = req.body;
      const result = await db
        .collection("users")
        .findOneAndUpdate(
          { _id: new ObjectId(req.user.userId) },
          { $set: { firstName, lastName, image, updatedAt: new Date() } },
          { returnDocument: "after" },
        );

      if (!result)
        return res.status(404).json({ error: "Nie znaleziono admina" });

      const { password, ...safeUser } = result;
      res.json({ message: "Profil zaktualizowany", user: safeUser });
    } catch (e) {
      res.status(500).json({ error: "Błąd serwera" });
    }
  },
);

async function startServer() {
  try {
    const port = process.env.PORT || (await findAvailablePort(3001));
    app.listen(port, () => console.log(`Serwer działa na porcie: ${port}`));
  } catch (e) {
    console.error(e);
  }
}
startServer();
