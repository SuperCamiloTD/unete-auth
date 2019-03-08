const mongoose = require('mongoose');
const { DB_CONN } = process.env;
const ObjectId = mongoose.Types.ObjectId;

mongoose.connect(DB_CONN, { useNewUrlParser: true });

const User = mongoose.model('User', {
    usernames: [String],
    password: String,
    creator: String
});

const Role = mongoose.model('Role', {
    name: String,
    permissions: []
});

const Permission = mongoose.model('Permission', {
    target: String,
    permissions: []
});

module.exports = { User, Role, Permission };