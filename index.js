process.on("uncaughtException", (err) => {
    // process.stderr.write("Error: " + err.message + "\n");
    process.stderr.write(err.stack + "\n");
    process.exit(1);
});

process.on("unhandledRejection", (err) => {
    throw err;
});

const path = require("path");
const util = require("util");
const r2promise = require("r2pipe-promise");

const gameInfo = require("./gameinfo");

const childProcessExec = util.promisify(require("child_process").exec);

function translateSignature(signature) {
    return signature.match(/\\x[a-f0-9]{2}|./ig)
        .map((c) => (c.length === 4) ? Number.parseInt(c.slice(2), 16) : c.charCodeAt(0))
        .map((o) => (o === 42) ? ".." : ("00" + o.toString(16)).substr(-2))
        .join("");
}

async function getDllDebugIdentifier(file) {
    // TODO: Make this safe.
    const cmd = await childProcessExec("objdump -p " + file + " | grep -A1 CodeView | tail -n 1");
    const debugInfo = cmd.stdout.trim().match(/^\(format [^ ]+ signature ([^ ]+) age ([^ ]+)\)$/);
    return debugInfo[1].toUpperCase() + (+debugInfo[2]).toString(16).toLowerCase();
}

async function getSoDebugIdentifier(file) {
    // TODO: Make this safe.
    const cmd = await childProcessExec("objdump -s -j .note.gnu.build-id " + file + " | grep -A2 'Contents of section' | tail -n 1");
    const debugInfo = cmd.stdout.trim().match(/^[0-9a-f]+ +([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8}) /);
    debugInfo[1] = debugInfo[1].match(/../g).reverse().join("");
    debugInfo[2] = debugInfo[2].match(/..../g).map((c) => c.match(/../g).reverse().join("")).join("");
    return (debugInfo[1] + debugInfo[2] + debugInfo[3] + debugInfo[4] + "0").toUpperCase();
}

function printSupportedGames() {
    process.stderr.write("Supported games:");
    for (const game of Object.keys(gameInfo)) {
        process.stderr.write(" " + game);
    }
    process.stderr.write("\n");
}

async function processFunction(r2, baseAddr, offset, name) {
    await r2.cmd("af " + offset + " " + offset);
    const info = (await r2.cmdj("afij " + offset))[0];

    if (!info) {
        return false;
    }

    let paramSize = 0;
    for (const bpvar of info.bpvars) {
        if (bpvar.kind !== "arg") {
            continue;
        }
        if (bpvar.type !== "int") {
            throw new Error("unknown bpvar arg type " + bpvar.type);
        }
        paramSize += 4;
    }
    for (const spvar of info.spvars) {
        if (spvar.kind !== "arg") {
            continue;
        }
        if (spvar.type !== "int") {
            throw new Error("unknown spvar arg type " + spvar.type);
        }
        paramSize += 4;
    }

    if (info.size < info.realsz) {
        process.stderr.write("Warning: size < realsz for " + name + ", possibly midfunc\n");
    }

    if ((info.offset & 0xF) !== 0) {
        process.stderr.write("Warning: Address not aligned to 16-bytes for " + name + ", possibly midfunc\n");
    }

    return {
        offset: info.offset - baseAddr,
        size: info.size,
        paramSize: paramSize,
        name: name,
    };
}

const args = process.argv.slice(2);
if (args.length !== 3) {
    process.stderr.write("Usage: <binary path> <game> <gamedata path>\n");
    printSupportedGames();
    process.exit(1);
}

if (!gameInfo[args[1]]) {
    process.stderr.write("Error: " + args[1] + " is not a supported game\n");
    printSupportedGames();
    process.exit(1);
}

(async function() {
    const r2 = await r2promise.open(args[0]);
    const binaryInfo = await r2.cmdj("iIj");

    let platform = binaryInfo.os;
    if (binaryInfo.bits !== 32) {
        platform += binaryInfo.bits;
    }

    const gamedataParser = require("./gamedata-parser")(platform, gameInfo[args[1]]);
    const gamedata = await gamedataParser.loadAll(args[2]);

    const output = [];

    for (const file of gamedata) {
        for (const key in file.signatures) {
            const name = file.name + "::" + key;
            const signature = translateSignature(file.signatures[key]);

            const search = await r2.cmdj("/xj " + signature);
            if (search.length === 0) {
                process.stderr.write("Warning: Failed to find match for " + name + "\n");
                continue;
            } else if (search.length > 1) {
                process.stderr.write("Warning: Multiple matches found for " + name + "\n");
            }

            const result = search[0];
            const func = await processFunction(r2, binaryInfo.baddr, result.offset, name);
            if (!func) {
                continue;
            }

            output.push(func);
        }
    }

    const exports = await r2.cmdj("iEj");

    for (const exprt of exports) {
        if (exprt.type !== "FUNC") {
            continue;
        }

        let name = exprt.name;
        if (binaryInfo.bintype === "pe") {
            name = name.match(/_(.*)$/)[1];
            let demangledName = (await r2.cmd("\"iD msvc " + name + "\"")).trim();
            demangledName = demangledName.match(/^[^:]+: [^ ]+ [^ ]+ (.+)$/);
            if (demangledName) {
                name = demangledName[1];
            }
        }

        const func = await processFunction(r2, binaryInfo.baddr, exprt.vaddr, name);
        if (!func) {
            continue;
        }

        output.push(func);
    }

    r2.quit();

    let headerPlatform = "unknown";
    let headerArch = "unknown";
    let headerDebugIdentifier = null;
    let headerDebugName = path.basename(args[0]);

    if (binaryInfo.os === "linux") {
        headerPlatform = "Linux";
        headerDebugIdentifier = await getSoDebugIdentifier(args[0]);
    } else if (binaryInfo.os === "windows") {
        headerPlatform = "windows";
        // headerDebugIdentifier = binaryInfo.guid; // https://github.com/radare/radare2/pull/11805
        headerDebugIdentifier = await getDllDebugIdentifier(args[0]);
        headerDebugName = path.basename(binaryInfo.dbg_file);
    }

    if (binaryInfo.arch === "x86" && binaryInfo.bits === 32) {
        headerArch = "x86";
    } else if (binaryInfo.arch === "x86" && binaryInfo.bits === 64) {
        headerArch = "x86_64";
    }

    process.stdout.write([
        "MODULE",
        headerPlatform,
        headerArch,
        headerDebugIdentifier,
        headerDebugName,
        "\n",
    ].join(" "));

    output.sort((a, b) => a.offset - b.offset);

    for (const func of output) {
        process.stdout.write([
            "FUNC",
            func.offset.toString(16),
            func.size.toString(16),
            func.paramSize.toString(16),
            func.name,
            "\n",
        ].join(" "));
    }
})();