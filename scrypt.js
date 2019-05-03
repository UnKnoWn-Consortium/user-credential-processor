const crypto = require("crypto");

const defaults = {
    /**
     * Desired Length of the generated hash
     */
    keyLength: 64,

    /**
     * A larger salt means hashed passwords are more resistant to rainbow table, but
     * you get diminishing returns pretty fast.
     */
    saltBytes: 16,

    /**
     * CPU/memory cost parameter. Must be a power of two greater than one.
     */
    cost: 16384,

    /**
     * Block size parameter.
     */
    blockSize: 8,

    /**
     * Parallelization parameter.
     */
    parallelization : 1,

    /**
     * Memory upper bound. It is an error when (approximately) 128 * N (cost) * r (blockSize) > maxmem.
     */
    maxmem: 32 * 1024 * 1024
};

module.exports = class ScryptProcessor {
    /**
     * Create a Scrypt Credential Processor instance by type supplied.
     * @param {object} options - Configuration.
     */
    constructor (
        options
    ) {
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
                    return;
                }

                let hashed;
                try {
                    hashed = await new Promise(
                        (resolve, reject) => {
                            crypto.scrypt(
                                password,
                                salt,
                                temporalOptions.keyLength,
                                {
                                    cost: temporalOptions.cost,
                                    blockSize: temporalOptions.blockSize,
                                    parallelization: temporalOptions.parallelization
                                },
                                (e, hash) => {
                                    if (e) {
                                        reject(e);
                                        return;
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
                                    combined.writeUInt32BE(temporalOptions.keyLength, 4, true);

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
                    return;
                }

                resolve(hashed);
            }
        );
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
    compare (
        incoming,
        stored
    ) {
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

            // TODO: To be Updated for Scrypt
            /**
             *	verify the salt and hash against the password
             */
            crypto.scrypt(
                incoming,
                salt,
                iterations,
                hashBytes,
                digest,
                function (e, verify) {
                    if (e) {
                        reject(e);
                        return;
                    }
                    resolve(verify.toString("binary") === hash);
                }
            );
        });
    }
};
