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

app.get("/", (req, res) => {
  res.send(`<h1>Sign in to see content</h1>
        <a href='/login'>Login</a></br>
        <a href='/signup'>Sign Up</a></br>
        <a href='/logout'>Log Out</a>
        `);
});

app.use("/signup", (req, res) => {
  res.send(`
        <h1>Sign Up</h1>
        <form action='/submitUser' method='post'>
        <input name='username' type='text' placeholder='username'>
        <input name='password' type='password' placeholder='password'>
        <input name='email' type='email' placeholder='email address'>
        <button>Sign Up</button>
        </form>
        `);
});

app.post("/submitUser", async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;
  var email = req.body.email;

  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    password: Joi.string().max(20).required(),
    email: Joi.string().email().required(),
  });

  const validationResult = schema.validate({ username, password, email });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/loggingin");
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    username: username,
    password: hashedPassword,
    email: email,
  });
  console.log("Inserted user");

  req.session.authenticated = true;
  req.session.username = username;
  req.session.cookie.maxAge = expireTime;

  res.redirect("/members");
});

app.get("/blank", (req, res) => {
  let blank = req.query.blank;

  res.send(
    `
        <h1>` +
      blank +
      ` was blank</h1>
        <a href='/signup'>Retry</a>
        `,
  );
});

app.get("/login", (req, res) => {
  res.send(`
        <h1>Log In</h1>
        <form action='/loggingin' method='post'>
        <input name='email' type='email' placeholder='email address'>
        <input name='password' type='password' placeholder='password'>
        <button>Log In</button>
        </form>
        `);
});

app.post("/loggingin", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().email().required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ username: 1, password: 1, _id: 1 })
    .toArray();

  if (result.length != 1) {
    console.log("user not found");
    res.redirect("/login");
    return;
  }

  if (await bcrypt.compare(password, result[0].password)) {
    req.session.authenticated = true;
    req.session.username = result[0].username;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
    return;
  } else {
    res.redirect("/incorrect");
    return;
  }
});

app.get("/incorrect", (req, res) => {
  res.send(`
        <h1>Incorrect password</h1>
        <a href='/login'>Retry</a>
        `);
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/login");
  }

  var randomnumber = Math.floor(Math.random() * 3) + 1;

  var username = req.session.username;
  var src;

  if (randomnumber == 1) {
    src = "/1.png";
  } else if (randomnumber == 2) {
    src = "/2.png";
  } else if (randomnumber == 3) {
    src = "/3.png";
  }

  res.send(
    `
        <h1>Hi ${username}</h1>
        <img src='${src}'>
        <a href='logout'>Log Out</a>
        `,
  );
});

app.use(express.static(__dirname + "/public"));

app.use((req, res) => {
  res.status(404);
  res.send("Page not found - 404");
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
