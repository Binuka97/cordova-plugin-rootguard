/* global cordova, module */

var RootGuard = {
    SAFE: 0,
    COMPROMISED: 1,
    UNKNOWN: 2,

    /**
     * Backward-compatible binary API. Returns 1 only for COMPROMISED.
     * SAFE and UNKNOWN both return 0 so upgrades cannot create new lockouts.
     */
    checkSecurity: function(success, error) {
        cordova.exec(success, error, "RootGuard", "checkSecurity", []);
    },

    /** Returns one of SAFE (0), COMPROMISED (1), or UNKNOWN (2). */
    checkSecurityStatus: function(success, error) {
        cordova.exec(success, error, "RootGuard", "checkSecurityStatus", []);
    },

    /** Returns status plus non-sensitive diagnostic categories. */
    checkSecurityDetailed: function(success, error) {
        cordova.exec(success, error, "RootGuard", "checkSecurityDetailed", []);
    }
};

module.exports = RootGuard;
