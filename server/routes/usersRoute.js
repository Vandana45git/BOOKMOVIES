const router = require("express").Router();
const User = require("../models/userModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const authMiddleware = require("../middlewares/authMiddleware");

//register a new user
router.post("/register", async (req, res) => {
    try {
        // check if user already exists

        let userExists = await User.findOne({ email: req.body.email });
        if (userExists) {
            return res.send({
                success: false,
                message: "User already exists",
            });
        }

        // hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password, salt);
        req.body.password = hashedPassword;

        // save the user
        const newUser = new User(req.body);
        await newUser.save();
        res.send({
            message: "Registration Successful, Please login",
            success: true,
        });
    } catch (error) {
        res.send({
            message: error.message,
            success: false,
        });
    }
});

//login a user
router.post("/login", async (req, res) => {
    try {
      // check if user exists
      const user = await User.findOne({ email: req.body.email });
      if (!user) {
        return res.send({
          success: false,
          message: "User does not exist",
        });
      }

      // check if password is correct
    const validPassword = await bcrypt.compare(
        req.body.password,
        user.password
      );
      if (!validPassword) {
        return res.send({
          success: false,
          message: "Invalid password",
        });
      }
      // create and assign token
    const token = jwt.sign({ userId: user._id }, process.env.jwt_secret, {
        expiresIn: "1d",
      });
      res.send({
        message: "User logged in successfully",
        data: token,
        success: true,
      });
    } catch (error) {
      res.send({
        message: error.message,
        success: false,
      });
    }
  });

  // get user details by id

router.get("/get-current-user", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.body.userId).select('-passrord')
    res.send({
      message: "User details fetched successfully",
      data: user,
      success: true,
    });
  } catch (error) {
    res.send({
      message: error.message,
      success: false,
    });
  }
});

module.exports = router;





