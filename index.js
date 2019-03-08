require('dotenv').config();


const { JWT_SECRET, BCRYPT_ROUNDS, TOKEN } = process.env;
const { User, Role, Permission } = require('./db');

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const util = require('util');
const bcrypt_hash = util.promisify(bcrypt.hash);
const bcrypt_compare = util.promisify(bcrypt.compare);

/**
 * Rule: Method.name
 * Role: ~Role
 */

const Auth = module.exports = {

    Role: {
        async create (name, token) {
            await Auth.caller(token, "$Auth.Role.create");
            const role = await Role.findOne({ name });

            if(role) throw "ROLE_ALREADY_EXISTS";
            
            return await Role.create({ name, permissions: [] });
        },

        async setPermission (name, permission, token) {
            return await Auth.Role.setPermissions(name, [permission.toString()], token);
        },

        async setPermissions (name, permissions=[], token) {
            await Auth.caller(token, "$Auth.Role.setPermissions");
            const role = await Auth.Role.role(name, TOKEN);

            role.permissions = [...new Set([...role.permissions, ...permissions ])];

            await role.save();
            return role;
        },

        async removePermission (name, permission, token) {
            await Auth.caller(token, "$Auth.Role.removePermissions");
            const role = await Auth.Role.role(name, TOKEN);
            const index = role.permissions.indexOf(permission);

            if(index === -1) return role;
            role.permissions = [...role.permissions.slice(0, index), ...role.permissions.slice(index + 1)];

            await role.save();
            return role;
        },

        async role (name, token) {
            await Auth.caller(token, "$Auth.Role.role");
            const role = await Auth.findOne({ name });

            if(!role) throw "ROLE_NOT_FOUND";

            return role;
        }
    },

    User: {
        async setPermission (_id, permission, token) {
            await Auth.caller(token, "$Auth.User.setPermission");

            let permissions = await Permission.findOne({ target: _id });
            
            if(!permissions)
                return await Permission.create({ target: _id, permissions: [permission] })
            
            permissions.permissions = [...new Set([...permissions.permissions, permission ])];

            await permissions.save();
            return permissions;
        },

        async removePermission (_id, permission, token) {
            await Auth.caller(token, "$Auth.User.removePermission");

            let permissions = await Permission.findOne({ target: _id });
            
            if(!permissions)
                return await Permission.create({ target: _id, permissions: [] })
            
            const index = permissions.permissions.indexOf(permission);
            if(index === -1) return permission;
            
            permissions.permissions = [...permissions.permissions.slice(0, index), ...permissions.permissions.slice(index + 1)];
            
            await permissions.save();
            return permissions;
        },

        async clearPermissions (_id, token) {
            await Auth.caller(token, "$Auth.User.clearPermissions");

            let permissions = await Permission.findOne({ target: _id });
            
            if(!permissions)
                return await Permission.create({ target: _id, permissions: [] })

            permissions.permissions = [];
            
            await permissions.save();
            return permissions;
        }
    },

    async create (usernames, password, token) {
        const { target } = await Auth.caller(token, '$Auth.create');

        /* Transforms usernames to correct format */
        if(typeof usernames === "string") usernames = [usernames];
        if(!Array.isArray(usernames) || usernames.length === 0) throw "INVALID_USERNAMES";

        const _hash = await bcrypt_hash(password, +BCRYPT_ROUNDS);
        usernames = usernames.map((x) => x.toLowerCase());
        
        /* User exists? */
        if(await User.findOne({ usernames })) throw "USER_ALREADY_EXISTS";

        let user = await User.create({
            usernames,
            password: _hash,
            creator: target
        });

        delete user.password;

        return user;
    },

    async login (username, password) {
        const user = await User.findOne({ usernames: username.toString() });
        
        if(!user) throw "INVALID_CREDENTIALS";
        if(!await bcrypt_compare(password, user.password)) throw "INVALID_CREDENTIALS";

        return jwt.sign({ type: 'access', target: user._id }, JWT_SECRET);
    },

    async generateAdminToken (token, target='$admin') {
        try {
            await Auth.caller(token, "$Auth.generateAdminToken")
        } catch(exc) {
            if(token !== JWT_SECRET) throw "UNAUTHORIZED";
        }

        return jwt.sign({ type: 'access', target, permissions: ["*"] }, JWT_SECRET);
    },

    async caller (token, method) {
        const decoded = await Auth.decode(token);

        if(await Auth.isAllowed(token, method)) return decoded;
        
        throw "UNAUTHORIZED";
    },

    async isAllowed (token, method) {
        if(token === TOKEN) return true;
        const permissions = await Auth.permissions(token);
        let admitted = false;

        for(const permission of permissions) {
            if(`-${method}` === permission || permission === "-*") return false;
            else if(method === permission || permission === "*") admitted = true;
        }

        return admitted;
    },

    async permissions (token) {
        const { target, permissions } = await Auth.decode(token);
        const _permissions = await Permission.findOne({ target });

        if(!_permissions) return [...(permissions || [])];

        let $permissions = [ ...(permissions || []), ..._permissions.permissions ];
        let ret = [];

        for(const $perm of $permissions) {
            if($perm[0] === "~") {
                const role = await Role.findOne({ name: $perm.substring(1) });

                if(!role) continue;

                ret = [...ret, ...role.permissions];
            } else ret.push($perm);
        }

        return ret;
    },

    decode (token) {
        try {
            return jwt.verify(token, JWT_SECRET);
        } catch (exc) {
            throw "UNAUTHORIZED";
        }
    }

}