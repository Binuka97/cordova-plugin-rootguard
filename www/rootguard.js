var RootGuard = {
    checkSecurity: function(success, error) {
        cordova.exec(success, error, "RootGuard", "checkSecurity", []);
    }
};

module.exports = RootGuard;
