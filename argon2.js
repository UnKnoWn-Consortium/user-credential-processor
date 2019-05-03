const argon2 = require("argon2");

module.exports = class Argon2Processor {
    /**
     * Create a bcryptLoginProcessor instance by options supplied.
     * @param {object} [options] - Optional options unique for Argon2; resort to default if not supplied.
     * @param {number} [options.timeCost] - Time cost (refer to Argon2 repo: https://github.com/P-H-C/phc-winner-argon2)
     * @param {number} [options.memoryCost] - Memory cost (refer to Argon2 repo: https://github.com/P-H-C/phc-winner-argon2)
     * @param {number} [options.parallelism] - Parallelism degree (refer to Argon2 repo: https://github.com/P-H-C/phc-winner-argon2)
     * @param {number} [options.type] - Argon2 variant (refer to Argon2 repo: https://github.com/P-H-C/phc-winner-argon2)
     * @param {boolean} [options.raw] - get the hash as a raw Node Buffer when true
     */
    constructor (
        options
    ) {
        if (
            options &&
            typeof options === "object"
        ) {
            this.options = options;
        } else {
            this.options = argon2.defaults;
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
    hash (
        password,
        options
    ) {
        let temporalOptions = this.options;

        if (
            options &&
            typeof options === "object"
        ) {
            temporalOptions = options;
        }

        return argon2.hash(password, temporalOptions);
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
     * @param {object} [options] - Optional options that overrides options supplied at constructor.
     * @return {IncomingPasswordHashComparePromise} A promise for comparing an incoming plain password with a hash
     */
    compare (
        incoming,
        stored,
        options
    ) {
        return new Promise(
            async (resolve, reject) => {
                let result;
                try {
                    result = await argon2.verify(stored, incoming);
                } catch (e) {
                    console.error(e);
                    reject(e);
                    return;
                }

                /*if (result) {
                    // check if rehashing is needed
                    let temporalOptions = this.options;

                    if (
                        options &&
                        typeof options === "object"
                    ) {
                        temporalOptions = options;
                    }

                    if (argon2.needsRehash(stored, temporalOptions)) {

                    }
                }*/

                resolve(result);
            }
        );
    }


};
