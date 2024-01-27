const express = require("express");
var bodyParser = require("body-parser");
require("dotenv").config();
const connectDB = require("./config/db");
const userRoutes = require("./routes/user");

const cors = require("cors");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const { isAuthincated } = require("./middleware/authincation");
// const Auth = require("./models/auth");
const app = express();

// parse application/json
app.use(bodyParser.json({ limit: "50mb" }));
// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false, limit: "50mb" }));

app.use(cors());
// app.use(express.json());
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(express.urlencoded({ extended: true }));

connectDB();

const PORT = process.env.PORT;

app.use("/api/user", userRoutes);

app.get("/", (req, res) => {
  res.send("<h1>HI-Here Backend API is working!</h1>");
});

app.listen(PORT, function () {
  console.log(`Server is listening on port ${PORT}`);
});
