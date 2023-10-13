const jwt = require("jsonwebtoken");
const User = require("./models/userModel");

module.exports = async (req, res, next) => {
  try {
    const authorizationHeader = req.get("Authorization");
    const token = authorizationHeader.replace("Bearer ", "");

    const payload = jwt.verify(token, "secret-key");
    const user = await User.findById(payload.id);

    if (!user || user.token !== token) {
      return res.status(401).json({ message: "Not authorized" });
    }

    if (!user.verify) {
      return res.status(401).json({ message: "Email not verified" });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: "Not authorized" });
  }
};
