//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser')
const ejs = require('ejs')
const mongoose = require('mongoose');
const session = require('express-session')
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');

const GoogleStrategy = require('passport-google-oauth2').Strategy;
const findOrCreate = require('mongoose-findorcreate')

// const encrypt = require('mongoose-encryption')
// const md5 = require('md5');
const bcrypt = require('bcrypt')
const saltRounds = 10;


const app = express();

app.use(express.static("public"));

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
    extended: true
}))

//put it here it is important

app.use(session({
    secret: "I am going to be a web developer in 6 months",
    resave: false,
    saveUninitialized :false
}))

app.use(passport.initialize());
app.use(passport.session())


mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true})
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String,
    secret: String,
});

//use passport local as the encryption way

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate)
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]})

const User = new mongoose.model("User", userSchema);

//Serialise
//deserialise who this user is and authenticate who is this user
passport.use(User.createStrategy())

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });
//put the google-passport code here
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    passReqToCallback   : true
  },
  function(request, accessToken, refreshToken, profile, done) {
      console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));
app.get("/", function(req, res) {
    res.render("home");
})

app.get("/auth/google", passport.authenticate("google", {scope:
         [ 'https://www.googleapis.com/auth/plus.login'] } 
));

app.get("/auth/google/secrets",
    passport.authenticate("google", {failureRedirect: "/login"}),
    function(req, res) {
        res.redirect('/secrets');
    }
)
app.get("/login", function(req, res) {
    res.render("login");
})

app.get("/register", function(req, res) {
    res.render("register");
})
app.get("/secrets", function(req, res) {
    //Anyone can see the secrets

    User.find({"secret":{$ne: null}}, function(err, foundUser){
        if(err) {
            console.log(err);
        } else{
            if(foundUser) {
                res.render("secrets", {usersWithSecrets: foundUser})
            }

        }

    });
})
app.get('/submit', function(req, res) {
    if(req.isAuthenticated()) {
        res.render("submit");
    } else{
        res.redirect("/login");
    }

})

app.post('/submit', function(req, res) {
    const submittedSecret = req.body.secret;
    console.log(req.user._id);

    User.findById(req.user.id, function(err, foundUser) {
        if(err) {
            console.log(err);
        } else{
            if(foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(function() {
                    res.redirect("/secrets");
                });
            }
        }
    })
})
app.get("/logout", function(req,res) {
    req.logout();
    res.redirect("/");
})

app.post('/register', function(req, res) {
    User.register({username: req.body.username, active: false},
        req.body.password, function(err,user) {
            if(err) {
                console.log(err)
                res.redirect("/register");
            } else{
                passport.authenticate("local")(req, res, function(){
                    res.redirect("/secrets");
                })
            }
            // var authenticate = User.authenticate();
            // authenticate(req.body.username, req.body.passport, function(err, result) {
            //     if(err) {
            //         console.log(err)
            //     } else{
            //         console.log('logged in successfully')
            //     }
            // })

        })

    // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    //     const newUser = new User({
    //         email: req.body.username,
    //         password: hash
    //     })
    //     newUser.save(function(err) {
    //         if(err) {
    //             console.log(err);
    //         } else{
    //             res.render("secrets");
    //         }
    //     })
    // })
    
    //const newUser = new User({
      //  email: req.body.username,
      //  password: md5(req.body.password)
    //})
    

})
app.post('/login', function(req, res) {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    //login in with passport 
    req.login(user, function(err){
        if(err) {
            console.log(err);
        } else{
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            })
        }
    })

    // const username = req.body.username
    // const password = req.body.password

    // User.findOne({email: username},function(err, founduser) {
    //     if(err) {
    //         console.log(err)
    //     } else{
    //         bcrypt.compare(password, founduser.password , function(err, result) {
    //             if(result === true) {
    //                 res.render("secrets");
    //             }

    //         })
            
    //     }
    // })
})
app.listen(3000, function() {
    console.log('server has started on port 3000.')
})