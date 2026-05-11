const express = require("express");
const bcrypt = require("bcryptjs");
const User = require("../model/User");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const Session = require("../model/session");
const sendEmail = require("../services/mail");
const { generateOtp, getOtpHtml } = require("../utils/utils");
const OTP = require("../model/otp");

const register = async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const isUser = await User.findOne({ email });
    if (isUser) {
      return res.status(400).json({ message: "User Already Exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password, salt);

    const user = await User.create({
      name,
      email,
      password: hashPassword,
    });

    const otp = generateOtp();
    const html = getOtpHtml(otp);

    const otpHash = await bcrypt.hash(otp, salt);

    await OTP.create({
      email,
      user: user._id,
      otpHash,
    });

    await sendEmail(
      email,
      "Email Verification OTP",
      `Your OTP for email verification is: ${otp}`,
      html,
    );

    res.status(201).json({
      message: "User Registered Successfully",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        verified: user.verified,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server Error" });
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "User Doesnt Exists" });
    }

    if (!user.verified) {
      return res.status(400).json({ message: "Email Not Verified" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid Credentials" });
    }

    const refreshToken = jwt.sign(
      {
        id: user._id,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      },
    );

    const salt = await bcrypt.genSalt(10);
    const refreshTokenHash = await bcrypt.hash(refreshToken, salt);

    const session = await Session.create({
      user: user._id,
      refreshTokenHash,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    const accessToken = jwt.sign(
      {
        id: user._id,
        sessionId: session._id,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "15m",
      },
    );

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      message: "User LoggedIn Successfully",
      accessToken,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server Error" });
  }
};

const refreshToken = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({ message: "No Refresh Token Provided" });
    }
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);

    const salt = await bcrypt.genSalt(10);
    const refreshTokenHash = await bcrypt.hash(refreshToken, salt);

    const sessions = await Session.find({
      revoked: false,
    });

    let matchedSession = null;

    for (const session of sessions) {
      const isMatch = await bcrypt.compare(
        refreshToken,
        session.refreshTokenHash,
      );

      if (isMatch) {
        matchedSession = session;
        break;
      }
    }

    if (!matchedSession) {
      return res.status(400).json({
        message: "Invalid Refresh Token",
      });
    }

    const accessToken = jwt.sign(
      {
        id: decoded.id,
        sessionId: matchedSession._id,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "15m",
      },
    );

    const newRefreshToken = jwt.sign(
      { id: decoded.id },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      },
    );

    const newRefreshTokenHash = await bcrypt.hash(newRefreshToken, salt);

    matchedSession.refreshTokenHash = newRefreshTokenHash;

    await matchedSession.save();
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res
      .status(200)
      .json({ message: "Access Token Refreshed Successfully", accessToken });
  } catch (err) {
    console.log(err);
    res.status(403).json({ message: "Invalid Refresh Token" });
  }
};

const logout = async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({ message: "No Refresh Token Provided" });
    }

    const sessions = await Session.find({
      revoked: false,
    });

    let matchedSession = null;

    for (const session of sessions) {
      const isMatch = await bcrypt.compare(
        refreshToken,
        session.refreshTokenHash,
      );

      if (isMatch) {
        matchedSession = session;
        break;
      }
    }
    if (!matchedSession) {
      return res.status(400).json({ message: "Invalid Refresh Token" });
    }

    matchedSession.revoked = true;
    await matchedSession.save();

    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });

    return res.status(200).json({ message: "Logged Out Successfully" });
  } catch (err) {
    console.error("Logout Error:", err);
    res.status(500).json({ message: "Server Error" });
  }
};

const logoutAll = async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({ message: "No Refresh Token Provided" });
    }

    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);

    await Session.updateMany(
      {
        user: decoded.id,
        revoked: false,
      },
      {
        revoked: true,
      },
    );

    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });

    return res
      .status(200)
      .json({ message: "Logged Out All Users Successfully" });
  } catch (err) {
    console.error("LogoutAll Error:", err);
    res.status(500).json({ message: "Server Error" });
  }
};

const verifyEmail = async (req, res) => {
  const { email, otp } = req.body;
  try {
    const salt = await bcrypt.genSalt(10);
    const otpHash = await bcrypt.hash(otp, salt);

    const otpDoc = await OTP.findOne({ email }).sort({ createdAt: -1 });
    if (!otpDoc) {
      return res.status(400).json({ message: "OTP Not Found" });
    }

    const user = await User.findByIdAndUpdate(otpDoc.user, {
      verified: true,
    });

    await OTP.deleteMany({ email });

    res.status(200).json({
      message: "Email Verified Successfully",
      user: {
        id: user._id,
        email: user.email,
        verified: user.verified,
      },
    });
  } catch (err) {
    console.error("VerifyEmail Error:", err);
    res.status(500).json({ message: "Server Error" });
  }
};

module.exports = {
  register,
  login,
  refreshToken,
  logout,
  logoutAll,
  verifyEmail,
};
