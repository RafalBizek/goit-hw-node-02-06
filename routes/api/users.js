const express = require("express");
const router = express.Router();
const User = require("../../models/userModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const authMiddleware = require("../../authMiddleware");
const multer = require("multer");
const Jimp = require("jimp");
const path = require("path");
const fs = require("fs").promises;
const gravatar = require("gravatar");
const sgMail = require("@sendgrid/mail");
const { v4: uuidv4 } = require("uuid");

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const storage = multer.diskStorage({
  destination: "tmp",
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({ storage });

router.post("/signup", async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(409).json({ message: "Email in use" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const avatarURL = gravatar.url(email, { s: "250", r: "pg", d: "404" });
    const verificationToken = uuidv4();
    const user = await User.create({
      email,
      password: hashedPassword,
      avatarURL,
      verificationToken,
    });

    const msg = {
      to: user.email,
      from: "rafal.bizek@gmail.com",
      subject: "Email Verification",
      text: `Click the link to verify your email: ${process.env.BASE_URL}/users/verify/${verificationToken}`,
      html: `<strong>Click the link to verify your email:</strong> <a href="${process.env.BASE_URL}/users/verify/${verificationToken}">Verify</a>`,
    };

    // Wysyłanie e-maila
    sgMail
      .send(msg)
      .then(() => {
        const token = jwt.sign({ id: user._id }, "secret-key", {
          expiresIn: "1h",
        });
        User.findByIdAndUpdate(user._id, { token });
        res.status(201).json({
          user: {
            email: user.email,
            subscription: user.subscription,
            avatarURL: user.avatarURL,
          },
        });
      })
      .catch((error) => {
        console.error("Error sending email:", error);
        // Usuń użytkownika, jeśli nie można wysłać e-maila
        User.findByIdAndDelete(user._id);
        res.status(500).json({ message: "Error sending verification email" });
      });
  } catch (error) {
    next(error);
  }
});

router.get("/logout", authMiddleware, async (req, res, next) => {
  try {
    await User.findByIdAndUpdate(req.user._id, { token: null });
    return res.status(204).end();
  } catch (error) {
    next(error);
  }
});

router.get("/current", authMiddleware, (req, res) => {
  const { email, subscription, avatarURL } = req.user;
  return res.status(200).json({ email, subscription, avatarURL });
});

router.patch(
  "/avatars",
  authMiddleware,
  upload.single("avatar"),
  async (req, res, next) => {
    try {
      const { file, user } = req;
      const img = await Jimp.read(file.path);
      await img.resize(250, 250).writeAsync(file.path);
      const avatarURL = `/avatars/${file.filename}`;
      await fs.rename(file.path, path.join("public", "avatars", file.filename));
      await User.findByIdAndUpdate(user._id, { avatarURL });
      res.status(200).json({ avatarURL });
    } catch (error) {
      next(error);
    }
  }
);

router.get("/verify/:verificationToken", async (req, res, next) => {
  try {
    const user = await User.findOne({
      verificationToken: req.params.verificationToken,
    });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    user.verify = true;
    user.verificationToken = null;
    await user.save();
    res.status(200).json({ message: "Verification successful" });
  } catch (error) {
    next(error);
  }
});

router.post("/verify/", async (req, res, next) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ message: "missing required field email" });
  }
  const user = await User.findOne({ email });
  if (user && !user.verify) {
    const msg = {
      to: user.email,
      from: "rafal.bizek@gmail.com",
      subject: "Email Verification",
      text: `Click the link to verify your email: ${process.env.BASE_URL}/users/verify/${user.verificationToken}`,
      html: `<strong>Click the link to verify your email:</strong> <a href="${process.env.BASE_URL}/users/verify/${user.verificationToken}">Verify</a>`,
    };

    sgMail.send(msg);

    return res.status(200).json({ message: "Verification email sent" });
  } else if (user && user.verify) {
    return res
      .status(400)
      .json({ message: "Verification has already been passed" });
  } else {
    return res.status(404).json({ message: "User not found" });
  }
});

module.exports = router;
