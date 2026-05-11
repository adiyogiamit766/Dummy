const express = require("express");
const morgan = require("morgan");
const cookieParser = require("cookie-parser");

const dotenv = require("dotenv");
require("dotenv").config();

const connectDB = require("./config/db");

const userRoutes = require("./router/userRoutes");

const app = express();
app.use(express.json());
app.use(morgan("dev"));
app.use(cookieParser());

connectDB();

app.get("/", (req, res) => {
  res.send("API is running...");
});

app.use("/api/auth", userRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
