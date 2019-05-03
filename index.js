/**
 * User credential processor
 * Created by Thomas Sham on 9/10/2017.
 */

module.exports = (hashingAlgorithm) => {
    let algorithm = Object.keys(hashingAlgorithm).filter(
        (key, ind, arr) => !!hashingAlgorithm[key]
    );

    if (algorithm.length > 1) {
        throw new Error("UserCredentialProcessor: More than one algorithm enabled. ");
    }

    let normalizedAlgorithm = algorithm[0].toLowerCase();

    switch (normalizedAlgorithm) {
        case "argon2": {
            const Argon2Processor = require("./argon2");
            return class UserCredentialProcessor extends Argon2Processor {};
        }

        case "bcrypt": {
            const BcryptProcessor = require("./bcrypt");
            return class UserCredentialProcessor extends BcryptProcessor {};
        }

        case "pbkdf2": {
            const PBKDF2Processor = require("./PBKDF2");
            return class UserCredentialProcessor extends PBKDF2Processor {};
        }

        case "scrypt": {
            const ScryptProcessor = require("./scrypt");
            return class UserCredentialProcessor extends ScryptProcessor {};
        }

        default: {
            throw new Error("UserCredentialProcessor: Unknown algorithm");
        }
    }
};
