process.on("uncaughtException", (err) => {
    // process.stderr.write("Error: " + err.message + "\n");
    process.stderr.write(err.stack + "\n");
    process.exit(1);
});

process.on("unhandledRejection", (err) => {
    throw err;
});

const path = require("path");
const r2promise = require("r2pipe-promise");

const gameInfo = require("./gameinfo");

function translateSignature(signature) {
    return signature.match(/\\x[a-f0-9]{2}|./ig)
        .map((c) => (c.length === 4) ? Number.parseInt(c.slice(2), 16) : c.charCodeAt(0))
        .map((o) => (o === 42) ? ".." : ("00" + o.toString(16)).substr(-2))
        .join("");
}

function printSupportedGames() {
    process.stderr.write("Supported games:");
    for (const game of Object.keys(gameInfo)) {
        process.stderr.write(" " + game);
    }
    process.stderr.write("\n");
}

async function processFunction(r2, baseAddr, offset, name, ref) {
    await r2.cmd("af " + offset + " " + offset);
    const info = (await r2.cmdj("afij " + offset))[0];

    if (!info) {
        process.stderr.write("Warning: Failed to create function from " + offset + " '" + name + "'\n");
        return false;
    }

    if (!ref) {
        ref = false;
    } else if (ref > (info.offset + info.size)) {
        process.stderr.write("Warning: " + ref + " '" + name + "' outside of created function bounds " + info.offset + " .. " + (info.offset + info.size) + ", probably missed the start\n");
        return false;
    } else {
        ref -= offset;
    }

    let paramSize = 0;
    for (const bpvar of info.bpvars) {
        if (bpvar.kind !== "arg") {
            continue;
        }
        if (bpvar.type !== "int32_t") {
            throw new Error("unknown bpvar arg type " + bpvar.type);
        }
        paramSize += 4;
    }
    for (const spvar of info.spvars) {
        if (spvar.kind !== "arg") {
            continue;
        }
        if (spvar.type !== "int32_t") {
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
        ref: ref,
    };
}

const args = process.argv.slice(2);
if (args.length !== 1 && args.length !== 4) {
    process.stderr.write("Usage: <binary path> [<game> <binary type> <gamedata path>]\n");
    printSupportedGames();
    process.stderr.write("Binary types: engine server matchmaking_ds etc.\n");
    process.exit(1);
}

if (args.length > 1 && !gameInfo[args[1]]) {
    process.stderr.write("Error: " + args[1] + " is not a supported game\n");
    printSupportedGames();
    process.exit(1);
}

function patchCommandWithTime(instance, id, func) {
    const old = instance[func];
    instance[func] = function(command) {
        const start = Date.now();
        return old.call(this, command).then(function(ret) {
            const duration = Date.now() - start;
            process.stderr.write("r2[" + id + "]." + func + "(" + command + ") = " + duration + "ms\n");
            return ret;
        });
    };
}

(async function() {
    const poolMax = require("os").cpus().length;
    process.stderr.write("Starting " + poolMax + " radare2 instances...");
    const pool = await Promise.all((new Array(poolMax)).fill(0).map(function() {
        return r2promise.open(args[0], ["-M"]);
    }));
    process.stderr.write(" done\n");

    let poolIdx = 0;
    function r2() {
        return pool[poolIdx++ % poolMax];
    }

    const binaryInfo = await r2().cmdj("iIj");

    const promises = [];
    const output = [];

    if (args.length >= 4) {
        let platform = binaryInfo.os;
        if (binaryInfo.bits !== 32) {
            platform += binaryInfo.bits;
        }

        const gamedataParser = require("./gamedata-parser")(platform, gameInfo[args[1]], args[2]);
        const gamedata = await gamedataParser.loadAll(args[3]);

        for (const file of gamedata) {
            for (const key in file.signatures) {
                promises.push((async function() {
                    const name = file.name + "::" + key;
                    const signature = translateSignature(file.signatures[key]);

                    const search = await r2().cmdj("/xj " + signature);
                    if (search.length === 0) {
                        process.stderr.write("Warning: Failed to find match for " + name + "\n");
                        return;
                    } else if (search.length > 1) {
                        process.stderr.write("Warning: Multiple matches found for " + name + "\n");
                    }

                    const result = search[0];

                    // Add a bit extra to the "ref" used for sorting, so exports are preferred.
                    const func = await processFunction(r2(), binaryInfo.baddr, result.offset, name, result.offset + 1);
                    if (!func) {
                        return;
                    }

                    output.push(func);
                })());
            }
        }
    }

    const exports = await r2().cmdj("iEj");

    for (const exprt of exports) {
        if (exprt.type !== "FUNC") {
            continue;
        }

        promises.push((async function() {
            let name = exprt.name;
            if (binaryInfo.bintype === "pe") {
                let demangledName = (await r2().cmd("\"iD msvc " + name + "\"")).trim();
                demangledName = demangledName.match(/^[^:]+: [^ ]+ [^ ]+ (.+)$/);
                if (demangledName) {
                    name = demangledName[1];
                }
            }

            const func = await processFunction(r2(), binaryInfo.baddr, exprt.vaddr, name, exprt.vaddr);
            if (!func) {
                return;
            }

            output.push(func);
        })());
    }

    const scannedNames = {};

    if (binaryInfo.os === "windows") {
        const imports = await r2().cmdj("iij");

        for (const imprt of imports) {
            if (imprt.type !== "FUNC") {
                continue;
            }

            if (!imprt.name.match(/\?EnterScope@CVProfile@@/)) {
                continue;
            }

            const search = await r2().cmdj("/adj call dword [0x" + imprt.plt.toString(16) + "]");

            for (const result of search) {
                promises.push((async function() {
                    const bytesBefore = 4096;
                    const bytesAfter = 32;

                    // The json-printing variants don't seem to work with negative offsets properly,
                    // so seek back in bytes and print forward. x86 instructions are self-synchronizing,
                    // so this works quite well, increase the window in case of synchronization problems.
                    const disassembly = await r2().cmdj("pDj " + (bytesBefore + bytesAfter) + " @ " + (result.offset - bytesBefore));

                    // Scan backwards through the disassembly to find the match
                    let i;
                    for (i = disassembly.length - 1; i >= 0; --i) {
                        if (disassembly[i].opcode === result.code) {
                            break;
                        }
                    }

                    if (i < 0) {
                        process.stderr.write("Warning: Failed to find searched instruction in disassembly from " + result.offset + "\n");
                        return;
                    }

                    // Scan backwards through the disassembly to find the 5 EnterScope arguments
                    const pushes = [];
                    for (--i; i >= 0; --i) {
                        if (disassembly[i].type === "push" || disassembly[i].type === "upush" || disassembly[i].type === "rpush") {
                            pushes.push(disassembly[i]);
                        }
                        if (pushes.length >= 5) {
                            break;
                        }
                    }

                    if (i < 0) {
                        process.stderr.write("Warning: Failed to find 5 push instructions in disassembly from " + result.offset + "\n");
                        return;
                    }

                    // Last arg is the string we want, only want absolute data refs.
                    if (pushes[0].type !== "push") {
                        // console.log("0x" + result.offset.toString(16), pushes[0]);
                        process.stderr.write("Warning: EnterScope call at " + result.offset + " does not push an absolute string ref\n");
                        return;
                    }

                    const name = "vprof::" + (await r2().cmd("psz @ " + pushes[0].ptr)).trim();

                    if (typeof scannedNames[name] === "undefined") {
                        scannedNames[name] = 1;
                    } else {
                        scannedNames[name]++;
                    }

                    // Scan backwards through the disassembly to find the start of the function (hopefully)
                    // This is a fairly lazy heuristic (depends on prior function alignment leaving dead space or ending in a ret)
                    for (--i; i >= 0; --i) {
                        if (((disassembly[i].opcode === "int3" && (disassembly[i + 1].type === "upush" || disassembly[i + 1].type === "rpush")) || (disassembly[i].type === "ret" && (disassembly[i + 1].opcode === "push esi" || disassembly[i + 1].opcode === "push ebx")) || disassembly[i + 1].opcode === "push ebp") && (disassembly[i + 1].offset & 0xF) === 0) {
                            ++i; // Push the cursor back onto the function boundary.
                            break;
                        }
                    }

                    if (i < 0) {
                        process.stderr.write("Warning: Failed to find start of function containing " + result.offset + " '" + name + "'\n");
                        return;
                    }

                    // ref the function against the first argument push, which is the "start" of the EnterScope call
                    // this is so the vprof result wins over the string search if we're doing both
                    const func = await processFunction(r2(), binaryInfo.baddr, disassembly[i].offset, name, pushes[pushes.length - 1].offset);
                    if (!func) {
                        return;
                    }

                    output.push(func);
                })());
            }

            break;
        }

        const strings = await r2().cmdj("izj");

        for (const string of strings) {
            if (string.type !== "ascii") {
                continue;
            }

            let name = string.string.match(/(?: in |^(?:Warning: ?|Error: ?)?)([CI][a-zA-Z_]+::~?[a-zA-Z_]+)/);

            if (!name) {
                continue;
            }

            name = name[1];

            // If this string exactly matches a vprof name we've already found, skip it to avoid probably duplicate work.
            if (typeof scannedNames["vprof::" + name] !== "undefined") {
                continue;
            }

            name = "string::" + name;

            if (typeof scannedNames[name] === "undefined") {
                scannedNames[name] = 1;
            } else {
                scannedNames[name]++;
            }

            promises.push((async function() {
                const search = await r2().cmdj("/adj " + string.vaddr.toString(16));

                for (const result of search) {
                    const opcode = (await r2().cmdj("pdj 1 @ " + result.offset))[0];
                    if (opcode.type !== "push" && opcode.type !== "mov") {
                        continue;
                    }

                    const bytesBefore = 4096;
                    const bytesAfter = 32;

                    // The json-printing variants don't seem to work with negative offsets properly,
                    // so seek back in bytes and print forward. x86 instructions are self-synchronizing,
                    // so this works quite well, increase the window in case of synchronization problems.
                    const disassembly = await r2().cmdj("pDj " + (bytesBefore + bytesAfter) + " @ " + (result.offset - bytesBefore));

                    // Scan backwards through the disassembly to find the match
                    let i;
                    for (i = disassembly.length - 1; i >= 0; --i) {
                        if (disassembly[i].opcode === result.code) {
                            break;
                        }
                    }

                    if (i < 0) {
                        process.stderr.write("Warning: Failed to find searched instruction in disassembly from " + result.offset + "\n");
                        continue;
                    }

                    // Scan backwards through the disassembly to find the start of the function (hopefully)
                    // This is a fairly lazy heuristic (depends on prior function alignment leaving dead space or ending in a ret)
                    for (--i; i >= 0; --i) {
                        if (((disassembly[i].opcode === "int3" && (disassembly[i + 1].type === "upush" || disassembly[i + 1].type === "rpush")) || (disassembly[i].type === "ret" && (disassembly[i + 1].opcode === "push esi" || disassembly[i + 1].opcode === "push ebx")) || disassembly[i + 1].opcode === "push ebp") && (disassembly[i + 1].offset & 0xF) === 0) {
                            ++i; // Push the cursor back onto the function boundary.
                            break;
                        }
                    }

                    if (i < 0) {
                        process.stderr.write("Warning: Failed to find start of function containing " + result.offset + " '" + name + "'\n");
                        continue;
                    }

                    const func = await processFunction(r2(), binaryInfo.baddr, disassembly[i].offset, name, result.offset);
                    if (!func) {
                        continue;
                    }

                    output.push(func);
                }
            })());
        }
    }

    let done = 0;
    let last = 0;
    for (let i = 0; i < promises.length; ++i) {
        promises[i] = promises[i].then(function() {
            done++;
            let progress = (done / promises.length) * 100;
            if (progress - last > 5) {
                process.stderr.write("Progress: " + progress.toFixed(2) + "%\n");
                last = progress;
            }
        });
    }

    process.stderr.write("Waiting for " + promises.length + " promises...\n");
    await Promise.all(promises);

    let headerPlatform = "unknown";
    let headerArch = "unknown";
    let headerDebugIdentifier = null;
    let headerDebugName = path.basename(args[0]);

    if (binaryInfo.os === "linux") {
        headerPlatform = "Linux";

        const sections = await r2().cmdj("iSj");
        const buildIdSection = sections.find(section => section.name === ".note.gnu.build_id");
        const buildIdRaw = await r2().cmdj("pxj " + buildIdSection.size + " @ 0x" + buildIdSection.paddr.toString(16));
        const buildIdBytes = buildIdRaw.slice(16, 32).map((b) => ("0" + b.toString(16)).slice(-2).toUpperCase());
        const buildId = [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15].map(i => buildIdBytes[i]).join("") + "0";

        headerDebugIdentifier = buildId;
    } else if (binaryInfo.os === "windows") {
        headerPlatform = "windows";
        headerDebugIdentifier = binaryInfo.guid;
        headerDebugName = path.basename(binaryInfo.dbg_file);
    }

    if (binaryInfo.arch === "x86" && binaryInfo.bits === 32) {
        headerArch = "x86";
    } else if (binaryInfo.arch === "x86" && binaryInfo.bits === 64) {
        headerArch = "x86_64";
    }

    for (let i = 0; i < pool.length; ++i) {
        pool[i].quit();
    }

    process.stdout.write([
        "MODULE",
        headerPlatform,
        headerArch,
        headerDebugIdentifier,
        headerDebugName,
        "\n",
    ].join(" "));

    output.sort((a, b) => {
        if (a.offset < b.offset) {
            return -1;
        } else if (a.offset > b.offset) {
            return 1;
        } else {
            return a.ref - b.ref;
        }
    });

    const filtered = output.filter((d, i, a) => {
        /*if (d.name.match(/^vprof::/)) {
            const distance = d.ref / (d.size + 128); // Offset the size of very small functions.
            console.log(d.name, distance.toFixed(2));
        }*/

        if (d.name.match(/^(vprof|string)::/) && scannedNames[d.name] > 1) {
            d.name = "contains-inlined-" + d.name;
        }

        return i <= 0 || d.offset != a[i - 1].offset;
    });

    for (const func of filtered) {
        process.stdout.write([
            "FUNC",
            func.offset.toString(16),
            func.size.toString(16),
            func.paramSize.toString(16),
            func.name,
            // func.ref,
            "\n",
        ].join(" "));
    }
})();
