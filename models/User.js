const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRound = 10;
const jwt = require('jsonwebtoken');

const userSchema = mongoose.Schema({
    name: {
        type: String,
        maxlength: 50
    },
    email: {
        type: String,
        trim: true,
        unique: 1
    },
    password: {
        type: String,
        minlength: 5
    },
    lastname: {
        type: String,
        maxlength: 50
    },
    role: {
        type: Number,
        default: 0
    },
    image: String,
    token: {
        type: String
    },
    tokenExp: {
        type: Number
    }
});

userSchema.pre('save', function( next ) {

    var user = this;

    if (user.isModified('password')) {
        // 비밀번호를 암호화 시킨다.
        bcrypt.genSalt(saltRound, function (err, salt) {
            if (err) return next(err);

            bcrypt.hash(user.password, salt, function (err, hash) {
                if (err) return next(err);
                user.password = hash;
                next();
            });
        });
    } else {
        next();
    }
})

userSchema.methods.comparePassword = function (plainPassword, callbackFn) {

    bcrypt.compare(plainPassword, this.password, function (err, isMatch) {
        if (err) return callbackFn(err);
        callbackFn(null, isMatch);
    });

}

userSchema.methods.generateToken = function (callbackFn) {

    var user = this;

    //jsonwebtoken을 이용해서 token을 생성한다.

    var token = jwt.sign(user._id.toHexString(), 'secretToken');

    user.token = token
    user.save(function(err, user) {
        if (err) return callbackFn(err)
        callbackFn(null, user)
    });
}

userSchema.statics.findByToken = function (token, callbackFn) {
    var user = this;
    // 토큰을 Decode한다.
    jwt.verify(token, 'secretToken', function (err, decoded) {
        // 유저 ID를 이용해서 유저를 찾은 다음에
        // 클라이언트에서 가져온 Token과 DB에 보관된 Token이 일치하는지 확인한다.

        user.findOne({"_id" : decoded, "token" : token}, function (err, user) {
            if (err) return callbackFn(err);
            callbackFn(null, user);
        });
    });
}

const User = mongoose.model('User', userSchema);

module.exports = {User};