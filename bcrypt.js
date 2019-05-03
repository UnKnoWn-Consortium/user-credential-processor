const bcrypt = require("bcrypt");

module.exports = class BcryptProcessor {
    /**
     * Create a bcryptLoginProcessor instance by options supplied.
     * @param {object} [options] - Optional options unique for bcrypt; resort to default if not supplied.
     * @param {number} [options.saltRounds] - The cost of processing the data. For details, refer to https://github.com/kelektiv/node.bcrypt.js#a-note-on-rounds
     */
    constructor (options) {
        if (
            !!options &&
            typeof options === "object" &&
            options.hasOwnProperty("saltRounds")
        ){
            this.options = options;
        }else{
            this.options = {
                saltRounds: 10
            };
        }
    }

    /**
     * A promise for the hashed password by the options supplied to the hashing function.
     *
     * @promise PaswordHashingPromise
     * @fulfill {string} The hashed password.
     * @reject {Error} Internal error of the hashing function. Check the returned error for details.
     *
     * Hash a password by the options supplied.
     * @param {string} password - Password.
     * @param {object} [options] - Optional options that overrides options supplied at constructor.
     * @return {PaswordHashingPromise} A promise for the hashed password by the options supplied to the hashing function.
     */
    hash (password, options) {
        let temporalOptions = this.options;
        if (!!options && typeof options === "object" && options.hasOwnProperty("saltRounds")) temporalOptions = options;
        return bcrypt.hash(password, temporalOptions.saltRounds);
    }

    /**
     * A promise for comparing an incoming plain password with a hash.
     *
     * @promise IncomingPasswordHashComparePromise
     * @fulfill {boolean} Whether the incoming plain password and the hash is a match.
     * @reject {Error} Internal error of the hashing function. Check the returned error for details.
     *
     * Compare an incoming password with the stored password hash.
     * @param {string} incoming - Incoming password.
     * @param {string} stored - Password hash stored in database.
     * @return {IncomingPasswordHashComparePromise} A promise for comparing an incoming plain password with a hash
     */
    compare (incoming, stored) {
        return bcrypt.compare(incoming, stored);
    }
};
