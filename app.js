require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate= require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: "Our little scret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String
});


userSchema.plugin(passportLocalMongoose, { usernameField: "email" });
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function (user, done) {
  done(null, user._id); // ✅ Save MongoDB ID in session
});

passport.deserializeUser(async function (id, done) {
  try {
    const user = await User.findById(id);
    done(null, user); // ✅ Load user by ID and attach to req.user
  } catch (err) {
    done(err);
  }
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", async function (req, res) {
    res.render("home");
});

app.get("/auth/google", 
    passport.authenticate("google", {scope: ["profile"]})
);

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect sescrets.
    res.redirect('/secrets');
  });

app.get("/login", async function (req, res) {
    res.render("login");
});

app.get("/register", async function (req, res) {
    res.render("register");
});

app.get("/secrets", function (req, res) {
    // console.log("Session:", req.session);
    // console.log("User from session:", req.user);
    // console.log("Authenticated?", req.isAuthenticated());

    if (req.isAuthenticated()) {
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
});

// app.get("/logout", function(req,res){
//     req.logout();
//     res.redirect("/");
// });

app.get("/logout", function (req, res, next) {
    req.logout(function (err) {
        if (err) return next(err);
        res.redirect("/");
    });
});


app.post("/register", async function (req, res) {
    // const username = req.body.username;
    // const password = req.body.password;
    try {
        const user = await User.register({ email: req.body.email }, req.body.password); // Correct object format

        // ✅ Automatically log the user in after registration
        req.login(user, function (err) {
            if (err) {
                console.error("Login after registration failed:", err);
                return res.redirect("/login");
            }
            res.redirect("/secrets");
        });
    } catch (err) {
        console.error("Registration error:", err.message);
        res.redirect("/register");
    }
});

app.post("/login", function (req, res, next) {
    passport.authenticate("local", function (err, user, info) {
        if (err) {
            console.error("Authentication error:", err);
            return next(err);
        }
        if (!user) {
            return res.redirect("/login"); // Invalid username or password
        }
        req.login(user, function (err) {

            if (err) {
                console.error("Login error:", err);
                return next(err);
            }
            return res.redirect("/secrets"); // ✅ Success
        });
    })(req, res, next);
});


// app.post("/login", async function (req, res) {
//     try{
//         const user = new User({
//         username: req.body.username,
//         password: req.body.password
//     });

//     req.login(user, function (err) {
//         if (err) {
//             console.error("Login after registration failed:", err);
//             return res.redirect("/login");
//         }
//         res.redirect("/secrets");
//     });
//     } catch (err) {
//         console.error("Registration error:", err.message);
//         res.redirect("/register");
//     }
// });

app.listen(3000, function () {
    console.log("Server started on port 3000");
});