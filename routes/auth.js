const router = require("express").Router();
const User = require("../models/User")
const CryptoJS = require('crypto-js')
const jwt = require('jsonwebtoken')

//Register
router.post("/register", async (req, res) => {
    try {
      // Check if a user with the provided email already exists
      const existingUser = await User.findOne({ email: req.body.email });
      if (existingUser) {
        // If a user with the email exists, return a 409 status code (Conflict) with an error message
        return res.status(409).json({ error: "Email is already taken. Please choose a different email." });
      }
  
      // If the email is not taken, proceed to create and save the new user
      const newUser = new User({
        username: req.body.username,
        email: req.body.email,
        password: CryptoJS.AES.encrypt(req.body.password, process.env.SECRET_KEY).toString()
      });
  
      const user = await newUser.save();
      res.status(201).json(user);
    } catch (error) {
      res.status(500).json(error);
    }
  });
  
//LOGIN

router.post("/login", async (req, res) => {
    try {
      const user = await User.findOne({ email: req.body.email });
  
      if (!user) {
        // If user is not found, respond with 401 status and an error object
        return res.status(401).json({ error: "Invalid Credentials" });
      }
  
      const bytes = CryptoJS.AES.decrypt(user.password, process.env.SECRET_KEY);
      const decrypted = bytes.toString(CryptoJS.enc.Utf8);
  
      if (decrypted !== req.body.password) {
        // If password doesn't match, respond with 401 status and an error object
        return res.status(401).json({ error: "Invalid Credentials" });
      }
  
      const accessToken = jwt.sign(
        { id: user.id, isAdmin: user.isAdmin },
        process.env.SECRET_KEY,
        { expiresIn: "1h" }
      );
      const { password, ...info } = user._doc;
  
      // Respond with 200 status and the user info (excluding the password) and the accessToken
      res.status(200).json({ ...info, accessToken });
    } catch (err) {
      res.status(500).json(err);
    }
  });
  

module.exports = router;