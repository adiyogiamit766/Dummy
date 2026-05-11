const mongoose = require("mongoose");

const otpSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "users",
      required: true,
    },
    otpHash: {
      type: String,
      required: true,
    },
  },
  { timestamps: true },
);

const OTP = mongoose.model("OTP", otpSchema);

module.exports = OTP;
