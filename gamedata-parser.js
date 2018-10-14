const fs = require("fs");
const path = require("path");
const util = require("util");

const smcParser = require("./smc-parser.js");

const fsReadFile = util.promisify(fs.readFile);
const fsStat = util.promisify(fs.stat);
const fsReaddir = util.promisify(fs.readdir);

async function readSmcFile(file) {
    try {
        const contents = await fsReadFile(file, "utf8");
        return smcParser.parse(contents);
    } catch (e) {
        throw new Error("Failed to parse " + file + ": " + e.message);
    }
}

module.exports = function(requiredPlatform, requiredGame) {
    let requiredEngine = null;
    let requiredEngines = (requiredGame.engine instanceof Array) ? requiredGame.engine : [ requiredGame.engine ];
    let requiredGameDirectory = requiredGame.directory && requiredGame.directory.toLowerCase();
    let requiredGameDescription = requiredGame.description && ("!" + requiredGame.description);
    let requiredGameName = requiredGame.name && ("$" + requiredGame.name);

    function doesGameMatch(game) {
        return game.toLowerCase() === requiredGameDirectory
            || game === requiredGameDescription
            || game === requiredGameName;
    }

    function restrictionsSatisfied(restrictions) {
        let hasGame = false;
        let matchedGame = false;
        let hasEngine = false;
        let matchedEngine = false;

        for (const restriction of restrictions) {
            switch (restriction.key) {
            case "game":
                hasGame = true;
                matchedGame = matchedGame || doesGameMatch(restriction.value);
                break;
            case "engine":
                hasEngine = true;
                matchedEngine = matchedEngine || restriction.value === requiredEngine;
                break;
            }
        }

        return (!hasGame || matchedGame) && (!hasEngine || matchedEngine);
    }

    async function parseLeafFile(file, output) {
        const data = await readSmcFile(file);

        for (const engine of requiredEngines) {
            requiredEngine = engine;

            for (const root of data) {
                if (root.key !== "Games") {
                    throw new Error("Expected 'Games' as root section of " + file);
                }

                for (const block of root.value) {
                    if (block.key !== "#default" && !doesGameMatch(block.key)) {
                        continue;
                    }

                    for (const section of block.value) {
                        if (section.key === "#supported") {
                            if (section !== block.value[0]) {
                                throw new Error("Expected '#supported' section to be first child of block in " + file);
                            }

                            if (!restrictionsSatisfied(section.value)) {
                                break;
                            }

                            continue;
                        }

                        switch (section.key) {
                        case "Keys":
                            for (const key of section.value) {
                                if (key.value instanceof Array) {
                                    for (const platform of key.value) {
                                        if (platform.key === requiredPlatform) {
                                            output.keys[key.key] = platform.value;
                                        }
                                    }
                                } else {
                                    output.keys[key.key] = key.value;
                                }
                            }
                            break;
                        case "Offsets":
                            for (const offset of section.value) {
                                for (const platform of offset.value) {
                                    if (platform.key === requiredPlatform) {
                                        output.offsets[offset.key] = platform.value;
                                    }
                                }
                            }
                            break;
                        case "Signatures":
                            for (const signature of section.value) {
                                for (const platform of signature.value) {
                                    if (platform.key === requiredPlatform) {
                                        output.signatures[signature.key] = platform.value;
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    async function parseMasterFile(file) {
        const data = await readSmcFile(path.join(file, "master.games.txt"));

        const leafFiles = [];
        for (const engine of requiredEngines) {
            requiredEngine = engine;

            for (const root of data) {
                if (root.key !== "Game Master") {
                    throw new Error("Expected 'Game Master' as root section of " + file);
                }

                for (const leafFile of root.value) {
                    if (!restrictionsSatisfied(leafFile.value)) {
                        continue;
                    }

                    leafFiles.push(leafFile.key);
                }
            }
        }

        const output = {
            name: path.basename(file),
            keys: {},
            offsets: {},
            signatures: {},
        };

        for (const leafFile of leafFiles) {
            await parseLeafFile(path.join(file, leafFile), output);
        }

        return output;
    }

    return {
        load: async function load(file) {
            const fileStat = await fsStat(file);

            if (fileStat.isDirectory()) {
                return parseMasterFile(file);
            } else {
                const output = {
                    name: path.basename(file, ".txt"),
                    keys: {},
                    offsets: {},
                    signatures: {},
                };

                await parseLeafFile(file, output);

                return output;
            }
        },
        loadAll: async function loadAll(file) {
            const children = await fsReaddir(file);
            const files = children.map((child) => this.load(path.join(file, child)));
            return Promise.all(files);
        }
    };
};