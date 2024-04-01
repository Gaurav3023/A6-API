const express = require('express');
const app = express();
const cors = require("cors");
const dotenv = require("dotenv");
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const passportJWT = require('passport-jwt');

dotenv.config();

mongoose.connect(process.env.MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));

const ExtractJWT = passportJWT.ExtractJwt;
const JWTStrategy = passportJWT.Strategy;

passport.use(new JWTStrategy({
    jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET
}, (jwtPayload, done) => {
    return done(null, jwtPayload);
}));

const userService = require("./user-service.js");

const HTTP_PORT = process.env.PORT || 8080;

app.use(express.json());
app.use(cors());
app.use(passport.initialize());

app.post("/api/user/register", (req, res) => {
    userService.registerUser(req.body)
        .then((msg) => {
            res.json({ "message": msg });
        }).catch((msg) => {
            res.status(422).json({ "message": msg });
        });
});

app.post("/api/user/login", (req, res) => {
    userService.checkUser(req.body)
        .then((user) => {
            const token = jwt.sign({ sub: user._id }, process.env.JWT_SECRET);
            res.json({ "message": "login successful", token });
        }).catch(msg => {
            res.status(422).json({ "message": msg });
        });
});

app.use("/api/user/favourites", passport.authenticate('jwt', { session: false }));
app.use("/api/user/history", passport.authenticate('jwt', { session: false }));

app.get("/api/user/favourites", (req, res) => {
    userService.getFavourites(req.user._id)
        .then(data => {
            res.json(data);
        }).catch(msg => {
            res.status(422).json({ error: msg });
        })
});

app.put("/api/user/favourites/:id", (req, res) => {
    userService.addFavourite(req.user._id, req.params.id)
        .then(data => {
            res.json(data)
        }).catch(msg => {
            res.status(422).json({ error: msg });
        })
});

app.delete("/api/user/favourites/:id", (req, res) => {
    userService.removeFavourite(req.user._id, req.params.id)
        .then(data => {
            res.json(data)
        }).catch(msg => {
            res.status(422).json({ error: msg });
        })
});

app.get("/api/user/history", (req, res) => {
    userService.getHistory(req.user._id)
        .then(data => {
            res.json(data);
        }).catch(msg => {
            res.status(422).json({ error: msg });
        })

});

app.put("/api/user/history/:id", (req, res) => {
    userService.addHistory(req.user._id, req.params.id)
        .then(data => {
            res.json(data)
        }).catch(msg => {
            res.status(422).json({ error: msg });
        })
});

app.delete("/api/user/history/:id", (req, res) => {
    userService.removeHistory(req.user._id, req.params.id)
        .then(data => {
            res.json(data)
        }).catch(msg => {
            res.status(422).json({ error: msg });
        })
});

app.listen(HTTP_PORT, () => {
    console.log("Server is running on port " + HTTP_PORT);
});
