var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');
var express = require('express');
var sessions = require("client-sessions");

var app = express();
app.use(express.static('./public'))

var sessionsMiddleware = sessions({
    cookieName: 'auth-cookie',  // front-end cookie name
    secret: 'DR@G0N$',        // the encryption password : keep this safe
    requestKey: 'session',    // we can access our sessions at req.session,
    duration: (86400 * 1000) * 7, // one week in milliseconds
    cookie: {
        ephemeral: false,     // when true, cookie expires when browser is closed
        httpOnly: true,       // when true, the cookie is not accesbile via front-end JavaScript
        secure: false         // when true, cookie will only be read when sent over HTTPS
    }
}) // encrypted cookies!
app.use(sessionsMiddleware)

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/** Database setup **/
mongoose.connect('mongodb://localhost/jail', function(err) {
    if( err ) {
        console.error('Could not connect to the Mongo Jailhouse!');
    } else {
        console.info("Connected to the Jailhouse!");
    }
});

var User = mongoose.model('user', {
    username : { type: String, required: true, unique: true },
    password : { type: String, required: true },
    role     : { type: String, required: true }
});

/*
app.get('/example', protected, function(req, res){ res.send('example'); });

function protected(req, res, next) {
    if( req.session.user.role === 'someRole' ) {
        // do something and call next()
    } else {
        // send down a forbidden response (status code 403)
    }
}
*/

var checkIfLoggedIn = function(req, res, next){
    if (req.session._id) {
        console.log("user is logged in. proceeding to next route handler")
        next()
    }
    else {
        res.redirect('/login')
    }
}

function allowedInLobby(req, res, next) {
    User.findById(req.session._id, function(err, user) {
        if (user.role !== 'prisoner') {
            console.log('Welcome to the lobby')
            next()
        } else {
            res.redirect('jail')
        }
    })
}

function allowedInCafeteria(req, res, next) {
    User.findById(req.session._id, function(err, user){
        if (user.role !== 'visitor') {
            console.log('Welcome to the cafeteria')
            next()
        } else {
            res.redirect('/jail')
        }   
    })

} //end func

function allowedInLounge(req, res, next) {
    User.findById(req.session._id, function(err, user){
        if (user.role !== 'prisoner') {
            console.log('Welcome to the lounge')
            next()
        } else {
            res.redirect('/jail')
        }   
    })

} //end func

function allowedInOffice(req, res, next) {
    User.findById(req.session._id, function(err, user){
        if (user.role === 'warden') {
            console.log('Welcome to your office')
            next()
        } else {
            res.redirect('/jail')
        }   
    })

} //end func

function allowedInCellE(req, res, next) {
    User.findById(req.session._id, function(err, user){
        name = user.username
        if (name === 'eve' || name === 'bob' || name === 'alice') {
            console.log('Welcome to cell E')
            next()
        } else {
            res.redirect('/jail')
        }   
    })

} //end func

function allowedInCellM(req, res, next) {
    User.findById(req.session._id, function(err, user){
        name = user.username
        if (name === 'mallory' || name === 'bob' || name === 'alice') {
            console.log('Welcome to cell M')
            next()
        } else {
            res.redirect('/jail')
        }   
    })

} //end func


app.get('/', function(req, res){
    res.sendFile('./html/login.html', {root:'./public'});
});
app.get('/jail', function(req, res, next){
    res.sendFile('./html/jail.html', {root:'./public'});
});
app.get('/lobby', allowedInLobby, function(req, res, next){
    res.sendFile('./html/lobby.html', {root:'./public'});
});
app.get('/visitors-lounge', allowedInLounge, function(req, res, next){
    res.sendFile('./html/visitors-lounge.html', {root:'./public'});
});
app.get('/cafeteria', allowedInCafeteria, function(req, res, next){
    res.sendFile('./html/cafeteria.html', {root:'./public'});
});
app.get('/wardens-office', allowedInOffice, function(req, res, next){
    res.sendFile('./html/wardens-office.html', {root:'./public'});
});
app.get('/cell-e', allowedInCellE, function(req, res, next){
    res.sendFile('./html/cell-e.html', {root:'./public'});
});
app.get('/cell-m', allowedInCellM, function(req, res, next){
    res.sendFile('./html/cell-m.html', {root:'./public'});
});

app.get('/me', function(req, res){
    User.findOne({_id: req.session._id}, function(err, user){
        res.send(user)
    })
})

app.post('/login', function(req, res) { // form post submission
    console.info('auth.login.payload:', req.body);
    
    User.findOne({ username: req.body.username }, function(err, user) {
        if( err) {
            console.log('MongoDB error:', err);
            res.status(500).send("failed to find user")
        }
        else if( !user ) {
            console.log('No user found!');
            res.status(403).send("<h1>Login failed</h1>");
        } else {
            console.log('auth.login.user', user);
            // at this point, user.password is hashed!
            bcrypt.compare(req.body.password, user.password, function(bcryptErr, matched) {
                // matched will be === true || false
                if( bcryptErr ) {
                    console.error('MongoDB error:', bcryptErr);
                    res.status(500).send("mongodb error");
                } else if ( !matched ) {
                    // forbidden, bad password
                    console.warn('Password did not match!');
                    res.status(403).send("failed to log in");
                } else {
                    req.session._id = user._id; // this is what keeps our user session on the backend!
                    res.send({ success: 'Login success' }); // send a success message
                }
            });
        }
    });
});        



app.listen('8080', function() {
    console.log('listening on 8080')
})


