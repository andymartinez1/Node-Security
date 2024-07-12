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

const app = express();

// Uses helmet request header security before any routes and Google OAuth
app.use(helmet());
app.use(passport.initialize());

function checkLoggedIn(req, res, next) {
  const isLoggedIn = true;
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
    session: false,
  }),
  (req, res) => {
    console.log("Google callback");
  }
);

// Logout
app.get("/auth/logout", (req, res) => {});

app.get("/secret", checkLoggedIn, (req, res) => {
  return res.send("Secret information");
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
