const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: [true, "Please enter your email"],
      unique: true,
      validate: [validator.isEmail, "Please enter valid email"],
    },
    password: {
      type: String,
      required: [true, "Please enter your password"],
      minLength: [8, "Password should be greater then 8 charaters"],
      select: false,
    },
    forgotPasswordOtp: {
      type: String,
      default: "",
    },
    forgotPasswordOtpExpire: {
      type: Date,
      default: "",
    },
    resetPasswordToken: {
      type: String,
      default: "",
    },
    resetPasswordTokenExpire: {
      type: Date,
      default: "",
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

// JWT TOKEN
userSchema.methods.getJWTToken = function () {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE,
  });
};

// compare forgot password
userSchema.methods.campareForgotPasswordOtp = async function (
  forgotPasswordOtp
) {
  const isMatch = await bcrypt.compare(
    forgotPasswordOtp,
    this.forgotPasswordOtp
  );
  return isMatch;
};

  module.exports = mongoose.model("user", userSchema);
