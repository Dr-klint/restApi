const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const port = process.env.PORT || 3000;

mongoose.connect("mongodb://localhost/shop");

const shopItemList = new mongoose.Schema({
  name: String,
  description: String,
  price: Number,
  isInStock: Boolean,
});

const userContent = new mongoose.Schema({
  fullName: String,
  username: String,
  password: String,
  role: String,
});

const ShopItem = mongoose.model("ShopItem", shopItemList);
const User = mongoose.model("User", userContent);

const authenticateUser = (req, res, next) => {
  const token = req.header("Authorization");

  if (!token) {
    return res
      .status(401)
      .json({ message: "Authentication failed: No token provided" });
  }

  try {
    const decoded = jwt.verify(token, "12345678");
    req.user = decoded;
    next();
  } catch (error) {
    return res
      .status(401)
      .json({ message: "Authentication failed: Invalid token" });
  }
};

module.exports = { authenticateUser };

app.use(bodyParser.json());

app.get("/api/shopitems", (req, res) => {
  ShopItem.find({})
    .then((shopItems) => res.json(shopItems))
    .catch((error) => res.status(500).json({ error: error.message }));
});

app.get("/api/shopitems/:id", (req, res) => {
  const itemId = req.params.id;
  ShopItem.findById(itemId)
    .then((shopItem) => {
      if (!shopItem) {
        return res.status(404).json({ message: "Item not found" });
      }
      res.json(shopItem);
    })
    .catch((error) => res.status(500).json({ error: error.message }));
});

app.post("/api/shopitems", authenticateUser, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Action not allowed" });
  }

  const newItem = new ShopItem(req.body);
  newItem
    .save()
    .then((item) => res.status(201).json(item))
    .catch((error) => res.status(400).json({ error: error.message }));
});

app.put("/api/shopitems/:id", authenticateUser, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Action not allowed" });
  }

  const itemId = req.params.id;
  ShopItem.findByIdAndUpdate(itemId, req.body, { new: true })
    .then((updatedItem) => {
      if (!updatedItem) {
        return res.status(404).json({ message: "Item not found" });
      }
      res.json(updatedItem);
    })
    .catch((error) => res.status(500).json({ error: error.message }));
});

app.delete("/api/shopitems/:id", authenticateUser, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Action not allowed" });
  }

  const itemId = req.params.id;
  ShopItem.findByIdAndDelete(itemId)
    .then((deletedItem) => {
      if (!deletedItem) {
        return res.status(404).json({ message: "Item not found" });
      }
      res.json({ message: "Item deleted" });
    })
    .catch((error) => res.status(500).json({ error: error.message }));
});

app.post("/api/register", async (req, res) => {
  const { fullName, username, password } = req.body;

  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    const newUser = new User({ fullName, username, password: hash });

    newUser
      .save()
      .then((user) => res.status(201).json(user))
      .catch((error) => res.status(400).json({ error: error.message }));
  });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  User.findOne({ username })
    .then((user) => {
      if (!user) {
        return res
          .status(401)
          .json({ message: "Authentication failed: User not found" });
      }

      bcrypt.compare(password, user.password, (err, result) => {
        if (err || !result) {
          return res
            .status(401)
            .json({ message: "Authentication failed: Invalid password" });
        }

        const token = jwt.sign(
          { userId: user._id, username: user.username, role: user.role },
          "12345678",
          { expiresIn: "1hour" }
        );

        res.json({ token });
      });
    })
    .catch((error) => res.status(500).json({ error: error.message }));
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
