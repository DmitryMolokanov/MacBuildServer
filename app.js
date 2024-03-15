const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const secretKey = "secret";

const app = express();

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "content-type");
  next();
});

app.use(express.json());

const userDataStorage = [];

app.post("/registration", async (req, res) => {
  try {
    const candidate = req.body.email;
    let duplicate = false;
    userDataStorage.forEach((el) => {
      if (el.email === candidate) duplicate = true;
    });
    if (duplicate) {
      res.sendStatus(401);
    } else {
      const hashPassword = await bcrypt.hash(req.body.password, 3);
      userDataStorage.push({ email: candidate, password: hashPassword });
      res.sendStatus(200);
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/authentication", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await userDataStorage.find((el) => {
      return el.email === email;
    });
    if (!user) {
      return res.status(401).json({ message: "User is not found" });
    }

    const isValidatePassword = bcrypt.compareSync(password, user.password);
    if (!isValidatePassword) {
      return res.status(401).json({ message: "Password is incorrect" });
    }
    const token = jwt.sign({ email }, secretKey, { expiresIn: "1h" });

    return res.status(200).json(token);
  } catch (err) {
    console.log(err);
  }
});

app.listen(3001, () => {
  console.log("Server started");
});
