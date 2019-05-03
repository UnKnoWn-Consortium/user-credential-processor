const crypto = require("crypto");

const defaults = {
    /**
     * size of the generated hash
     */
    hashBytes: 32,

    /**
     * A larger salt means hashed passwords are more resistant to rainbow table, but
     * you get diminishing returns pretty fast.
     */
    saltBytes: 16,

    /**
     * A selected HMAC digest algorithm specified by digest is applied to derive
     * a key of the requested byte length (keylen) from the password, salt and
     * iterations.
     * - sha512, sha256
     * - whirlpool
     * and more.
     */
    digest: "whirlpool",

    /**
     * More iterations means an attacker has to take longer to brute force an
     * individual password, so larger is better. however, larger also means longer
     * to hash the password. tune so that hashing the password takes about a
     * second.
     */
    iterations: 777777
};

module.exports = class PBKDF2Processor {
    /**
     * Create a bcryptLoginProcessor instance by options supplied.
     * @param {object} [options] - Optional options unique for PBKDF2; resort to default if not supplied.
     * @param {number} [options.hashBytes] -
     * @param {number} [options.saltBytes] -
     * @param {string} [options.digest] -
     * @param {number} [options.iterations] -
     */
    constructor (options) {
        if (options && typeof options === "object"){
            this.options = Object.assign(Object.assign({}, defaults), options);
        } else {
            this.options = defaults;
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
     * @param {!string} password - Password.
     * @param {object} [options] - Optional options that overrides options supplied at constructor.
     * @return {PaswordHashingPromise} A promise for the hashed password by the options supplied to the hashing function.
     */
    hash (
        password,
        options
    ) {
        let temporalOptions = this.options;
        if (options && typeof options === "object"){
            temporalOptions = Object.assign(Object.assign({}, defaults), options);
        }

        return new Promise(
            async (resolve, reject) => {
                let salt;
                try {
                    salt = await new Promise(
                        (resolve, reject) => {
                            crypto.randomBytes(
                                temporalOptions.saltBytes,
                                (e, salt) => {
                                    if (e) {
                                        reject(e);
                                    }
                                    resolve(salt);
                                }
                            );
                        }
                    )
                } catch (e) {
                    console.error(e);
                    reject(e);
                }

                let hashed;
                try {
                    hashed = await new Promise(
                        (resolve, reject) => {
                            crypto.pbkdf2(
                                password,
                                salt,
                                temporalOptions.iterations,
                                temporalOptions.hashBytes,
                                temporalOptions.digest,
                                (e, hash) => {
                                    if (e) {
                                        reject(e)
                                    }

                                    let combined = Buffer.alloc(hash.length + salt.length + 8);

                                    /**
                                     *  The size of the salt is also included so that we can figure out
                                     *  how long the salt is in the hash during verification
                                     */
                                    combined.writeUInt32BE(salt.length, 0, true);

                                    /**
                                     * Similarly, iteration count is included
                                     */
                                    combined.writeUInt32BE(temporalOptions.iterations, 4, true);

                                    salt.copy(combined, 8);
                                    hash.copy(combined, salt.length + 8);
                                    resolve(combined.toString("hex"));
                                }
                            );
                        }
                    );
                } catch (e) {
                    console.error(e);
                    reject(e);
                }

                resolve(hashed);
            }
        );
    };

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
        return new Promise((resolve, reject) => {
            let buffer = Buffer.from(stored, "hex");

            /**
             *	Extract the salt and hash from the combined buffer
             */
            let saltBytes = buffer.readUInt32BE(0);
            let salt = buffer.slice(8, saltBytes + 8);

            let hashBytes = buffer.length - saltBytes - 8;
            let iterations = buffer.readUInt32BE(4);
            let hash = buffer.toString("binary", saltBytes + 8);
            let digest = defaults.digest;

            /**
             *	verify the salt and hash against the password
             */
            crypto.pbkdf2(
                incoming,
                salt,
                iterations,
                hashBytes,
                digest,
                function (e, verify) {
                    if (e) {
                        reject(e);
                    }
                    resolve(verify.toString("binary") === hash);
                }
            );
        });
    }
};
