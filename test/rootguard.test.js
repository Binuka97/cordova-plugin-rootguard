"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const root = path.resolve(__dirname, "..");

function loadPlugin() {
    const calls = [];
    global.cordova = {
        exec(success, error, service, action, args) {
            calls.push({ success, error, service, action, args });
        }
    };
    const modulePath = path.join(root, "www", "rootguard.js");
    delete require.cache[require.resolve(modulePath)];
    return { plugin: require(modulePath), calls };
}

test("exports stable status constants", () => {
    const { plugin } = loadPlugin();
    assert.equal(plugin.SAFE, 0);
    assert.equal(plugin.COMPROMISED, 1);
    assert.equal(plugin.UNKNOWN, 2);
});

test("legacy and three-state actions call the native RootGuard service", () => {
    const { plugin, calls } = loadPlugin();
    const success = () => {};
    const error = () => {};

    plugin.checkSecurity(success, error);
    plugin.checkSecurityStatus(success, error);
    plugin.checkSecurityDetailed(success, error);

    assert.deepEqual(calls.map(({ service, action, args }) => ({ service, action, args })), [
        { service: "RootGuard", action: "checkSecurity", args: [] },
        { service: "RootGuard", action: "checkSecurityStatus", args: [] },
        { service: "RootGuard", action: "checkSecurityDetailed", args: [] }
    ]);
});

test("plugin metadata versions agree and JavaScript source exists with exact casing", () => {
    const packageJson = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    const pluginXml = fs.readFileSync(path.join(root, "plugin.xml"), "utf8");
    const match = pluginXml.match(/<plugin[^>]+version="([^"]+)"/);

    assert.ok(match);
    assert.equal(match[1], packageJson.version);
    assert.match(pluginXml, /src="www\/rootguard\.js"/);
    assert.ok(fs.existsSync(path.join(root, "www", "rootguard.js")));
    assert.equal(packageJson.types, "types/index.d.ts");
    assert.ok(fs.existsSync(path.join(root, packageJson.types)));
    assert.equal(packageJson.publishConfig.access, "public");
});

test("Android implementation does not execute shell commands or fail closed on exceptions", () => {
    const source = fs.readFileSync(path.join(root, "src", "android", "RootGuard.java"), "utf8");
    assert.doesNotMatch(source, /Runtime\.getRuntime\(\)\.exec|ProcessBuilder/);
    assert.match(source, /new Assessment\(UNKNOWN/);
    assert.match(source, /assessment\.status == COMPROMISED \? 1 : 0/);
    assert.match(source, /\/proc\/self\/maps/);
    assert.match(source, /\/proc\/self\/fd/);
    assert.match(source, /\/proc\/self\/task/);
    assert.match(source, /\/proc\/self\/net\/tcp6?/);
    assert.match(source, /AUTH\\r\\n/);
});

test("iOS does not use the stock /private/preboot directory as an indicator", () => {
    const source = fs.readFileSync(path.join(root, "src", "ios", "RootGuard.m"), "utf8");
    assert.doesNotMatch(source, /^\s*"\/private\/preboot",?$/m);
});
