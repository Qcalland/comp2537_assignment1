require("./utils.js");
require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const bcrypt = require("bcrypt");
const saltRounds = 12;

const Joi = require("joi");

const mongoSanitizer = require("mongo-sanitizer").default;

const app = express();
const PORT = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const { database } = include("databaseConnection");
const userCollection = database.db(mongodb_user_database).collection("users");

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: process.env.NODE_SESSION_SECRET,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
  }),
);

app.use(mongoSanitizer({ replaceWith: "_" }));

app.use("/", (req, res) => {
  res.send(`<h1>Sign in to see content</h1>
        <a href='/login'>Login</a></br>
        <a href='/signup'>Sign Up</a>
        `);
});

app.use("/signup", (req, res) => {});

app.post("/submitUser", async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;

  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ username, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/createUser");
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    username: username,
    password: hashedPassword,
  });
  console.log("Inserted user");

  res.redirect("/login");
});

app.use("/login", (req, res) => {});

app.use("/content", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/login");
  }
});

app.use(express.static(__dirname + "/public"));

app.use((req, res) => {
  res.status(404);
  res.send("Page not found - 404");
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
