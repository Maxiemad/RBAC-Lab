const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// Secret key for JWT signing
const JWT_SECRET = "newtonschoolsecret";

// In-memory user data
const users = [
  { username: "yash", password: "123", role: "admin" },
  { username: "ankit", password: "123", role: "teacher" },
  { username: "anurag", password: "123", role: "student" },
];

// --- LOGIN ROUTE ---
app.post("/login", (req, res) => {
  const {username,password} = req.body
  const user=users.find(i=>i.username===username && i.password===password)
  if (!user){
    return res.status(401).send("Invalid credentials")
  }
  const token=jwt.sign({username:user.username,role:user.role},JWT_SECRET,{expiresIn:"1h"})
  res.status(200).json({token})


  
});

// --- AUTH MIDDLEWARE ---
const authenticate = (req, res, next) => {
  const authHeader=req.headers.authorization
  if (!authHeader){
    return res.status(401).send("authorisation header miss")
  }
  const token=authHeader.split(" ")[1]
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).send("Invalid token")
    }
    req.user = user
    next()
  })
};

// --- ROLE CHECK MIDDLEWARE ---
const authorize = (allowedRoles) => (req, res, next) => {
  const userRole = req.user.role
  if (allowedRoles.includes(userRole)) {
    next();
  } else {
    res.status(403).send("Access denied");
  }
  next();
  
};

// --- PROTECTED ROUTES ---
app.get("/admin", authenticate, authorize(["admin"]), (req, res) => {
  res.send("Welcome, admin!");
});

app.get("/teacher", authenticate, authorize(["teacher"]), (req, res) => {
  res.send("Welcome, teacher!");
});

app.get("/student", authenticate, authorize(["student"]), (req, res) => {
  res.send("Welcome, student!");
});

module.exports = app;

// --- RUN DIRECTLY IF NOT TESTING ---
const PORT = 3300;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
