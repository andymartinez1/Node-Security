const cookieSession = require("cookie-session");
const express = require("express");
const fs = require("fs");
const helmet = require("helmet");
const https = require("https");
const passport = require("passport");
const path = require("path");
const { Strategy } = require("passport-google-oauth20");
const { verify } = require("crypto");

require("dotenv").config();

const PORT = 3000;

const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  COOKIE_KEY_1: process.env.COOKIE_KEY_1,
  COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

const AUTH_OPTIONS = {
  callbackURL: "/auth/google/callback",
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
};

function verifyCallback(accessToken, refreshToken, profile, done) {
  console.log("Google profile", profile);
  done(null, profile);
}

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

// Save the session to cookie using id for much smaller cookie size
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Read (load) the session from the cookie
passport.deserializeUser((id, done) => {
  //   User.findById(id).then((user) => {
  //     done(null, user);
  //   });
  done(null, id);
});

const app = express();

// Middleware for helmet request header security, cookie sessions and Google OAuth
app.use(helmet());
app.use(
  cookieSession({
    name: "session",
    maxAge: 24 * 60 * 60 * 1000, // 1 day
    keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2],
  })
);
app.use(passport.initialize());
app.use(passport.session());

function checkLoggedIn(req, res, next) {
  console.log("Current user is:", req.user);
  const isLoggedIn = req.isAuthenticated() && req.user;
  if (!isLoggedIn)
    return res.status(401).json({
      error: "You must log in",
    });
  next();
}

// Login
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["email"],
  })
);

// Redirect from Google auth server
app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/failure",
    successRedirect: "/",
    session: true, // Set to true by default
  }),
  (req, res) => {
    console.log("Google callback");
  }
);

// Logout
app.get("/auth/logout", (req, res) => {
  req.logout();
  return res.redirect("/");
});

app.get("/secret", checkLoggedIn, (req, res) => {
  return res.send("SECRET INFORMATION");
});

app.get("failure", (req, res) => {
  return res.send("Failed to log in");
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Using openssl to generate a free self-signed certificate and key
https
  .createServer(
    {
      key: fs.readFileSync("key.pem"),
      cert: fs.readFileSync("cert.pem"),
    },
    app
  )
  .listen(PORT, () => {
    console.log(`Listening on port: ${PORT}`);
  });
