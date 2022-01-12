require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')

const app = express();

app.use(express.static(__dirname+"/public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
  secret:process.env.SIGNN,
  resave:false,
  saveUninitialized:false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.DB_URI);

const userSchema = new mongoose.Schema({
	username:String,
	password:String,
  googleId:String,
  secret:String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.URI+"/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id}, function (err, user) {
      return cb(err, user);
    });
  }
));

// Route home
app.route("/")
.get((req,res)=>{
	res.render("home");
});

// Route google auth
app.route("/auth/google")
.get(passport.authenticate('google', { scope: ['profile'] }));

app.route("/auth/google/secrets")
.get(passport.authenticate('google', { failureRedirect: '/login' }),function(req, res) {
  // Successful authentication, redirect to secret.
  res.redirect('/secrets');
});

// Route secrets
app.route("/secrets")
.get((req,res)=>{
  User.find({secret:{$ne:null}},(err,found)=>{
    if(found){
      res.render("secrets",{allSecret:found});
    }else{
      console.log(err);
    }
  })
});

app.route("/submit")
.get((req,res)=>{
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
})
.post((req,res)=>{
  secretSubmit= req.body.secret;
  User.findById(req.user.id,(err,found)=>{
    if(found){
      found.secret=secretSubmit;
      found.save(()=>{
        res.redirect("/secrets");
      })
    }else{
      console.log(err);
    }
  })
});

// Route register
app.route("/register")
.get((req,res)=>{
  res.render("register");
})
.post((req,res)=>{
  User.register({username:req.body.username},req.body.password,(err,user)=>{
    if(err){
      console.log(err);
      res.redirect("/register");
    }else{
      passport.authenticate("local")(req,res,()=>{
        res.redirect("/secrets")
      })
    }
  })
});

// route login
app.route("/login")
.get((req,res)=>{
  res.render("login");
})
.post((req,res)=>{
  const email= req.body.username;
  const password= req.body.password;

  const user = new User({
    username:email,
    password:password
  });
  req.login(user,(err)=>{
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local",{ failureRedirect: '/login'})(req,res,()=>{
        res.redirect("secrets");
      })
    }
  })
});

// route logout
app.route("/logout")
.get((req,res)=>{
  req.logout();
  res.redirect("/");
});


app.listen(process.env.PORT||3000,()=>{
	console.log("We are in port 3000");
});