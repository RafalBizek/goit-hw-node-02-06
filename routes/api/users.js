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
    const user = await User.create({
      email,
      password: hashedPassword,
      avatarURL,
    });

    const token = jwt.sign({ id: user._id }, "secret-key", { expiresIn: "1h" });
    await User.findByIdAndUpdate(user._id, { token });

    return res.status(201).json({
      user: {
        email: user.email,
        subscription: user.subscription,
        avatarURL: user.avatarURL,
      },
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

module.exports = router;
