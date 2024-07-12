const express = require("express");
const fs = require("fs");
const helmet = require("helmet");
const https = require("https");
const path = require("path");

const PORT = 3000;

const app = express();

// Uses helmet request header security before any routes
app.use(helmet());

function checkLoggedIn(req, res, next) {
  const isLoggedIn = true;
  if (!isLoggedIn)
    return res.status(401).json({
      error: "You must log in",
    });
  next();
}

// Login
app.get("/auth/google", (req, res) => {});

// Redirect from Google auth server
app.get("/auth/google/callback", (req, res) => {});

// Logout
app.get("/auth/logout", (req, res) => {});

app.get("/secret", checkLoggedIn, (req, res) => {
  return res.send("Secret information");
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
