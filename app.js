require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const bcrypt = require("bcrypt");
const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String
});


userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = new mongoose.model("User", userSchema);

app.get("/", async function (req, res) {
    res.render("home");
});

app.get("/login", async function (req, res) {
    res.render("login");
});

app.get("/register", async function (req, res) {
    res.render("register");
});

app.post("/register", async function (req, res) {

    bcrypt.hash(req.body.password, saltRounds, async function (err, hash) {
        const newUser = new User({
            email: req.body.username,
            password: hash
        });

        try {
            await newUser.save();
            res.render("secrets");
        } catch (err) {
            console.error("Error saving user:", err);
            res.status(500).send("Registration failed: " + err.message);
        }
    });

});

app.post("/login", async function (req, res) {
    const username = req.body.username;
    const password = req.body.password  ;

    try {
        const foundUser = await User.findOne({ email: username });
        if (foundUser) {
            const match = await bcrypt.compare(password, foundUser.password);
            if (match) {
                res.render("secrets");
            } else {
                res.send("Incorrect password");
            }
        } else {
            res.send("No user found with this mail");
        }
    } catch (err) {
        console.log(err);
    }
});

app.listen(3000, function () {
    console.log("Server started on port 3000");
});