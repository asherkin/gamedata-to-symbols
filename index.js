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

(async function() {
    const r2 = await r2promise.open(args[0]);
    const binaryInfo = await r2.cmdj("iIj");

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
                const func = await processFunction(r2, binaryInfo.baddr, result.offset, name, result.offset + 1); // Add a bit extra to the "ref" used for sorting, so exports are preferred.
                if (!func) {
                    continue;
                }

                output.push(func);
            }
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

        const func = await processFunction(r2, binaryInfo.baddr, exprt.vaddr, name, exprt.vaddr);
        if (!func) {
            continue;
        }

        output.push(func);
    }

    if (binaryInfo.os === "windows") {
        const imports = await r2.cmdj("iij");

        for (const imprt of imports) {
            if (imprt.type !== "FUNC") {
                continue;
            }

            if (!imprt.name.match(/\.dll_\?EnterScope@CVProfile@@/)) {
                continue;
            }

            const search = await r2.cmdj("/cj call dword [0x" + imprt.plt.toString(16) + "]");

            for (const result of search) {
                const bytesBefore = 4096;
                const bytesAfter = 32;

                // The json-printing variants don't seem to work with negative offsets properly,
                // so seek back 100 bytes and print 128 bytes of instructions (x86 instructions are
                // self-synchronizing, so this works quite well, increase the window in case of
                // synchronization problems.)
                const disassembly = await r2.cmdj("pDj " + (bytesBefore + bytesAfter) + " @ " + (result.offset - bytesBefore));

                // Scan backwards through the disassembly to find the call
                let i;
                for (i = disassembly.length - 1; i >= 0; --i) {
                    if (disassembly[i].opcode === result.code) {
                        break;
                    }
                }

                if (i < 0) {
                    process.stderr.write("Warning: Failed to find call instruction in disassembly from " + result.offset + "\n");
                    continue;
                }

                // Scan backwards through the disassembly to find the 5 EnterScope arguments
                const pushes = [];
                for (--i; i >= 0; --i) {
                    if (disassembly[i].type === "push" || disassembly[i].type === "upush") {
                        pushes.push(disassembly[i]);
                    }
                    if (pushes.length >= 5) {
                        break;
                    }
                }

                if (i < 0) {
                    process.stderr.write("Warning: Failed to find 5 push instructions in disassembly from " + result.offset + "\n");
                    continue;
                }

                // Last arg is the string we want, only want absolute data refs.
                if (pushes[0].type !== "push") {
                    // console.log("0x" + result.offset.toString(16), pushes[0]);
                    process.stderr.write("Warning: EnterScope call at " + result.offset + " does not push an absolute string ref\n");
                    continue;
                }

                const str = (await r2.cmd("psz @ " + pushes[0].ptr)).trim();

                // Scan backwards through the disassembly to find the start of the function (hopefully)
                // This is a fairly lazy heuristic (depends on prior function alignment leaving dead space or ending in a ret)
                for (--i; i >= 0; --i) {
                    if (((disassembly[i].opcode === "int3" && disassembly[i + 1].type === "upush") || (disassembly[i].type === "ret" && (disassembly[i + 1].opcode === "push esi" || disassembly[i + 1].opcode === "push ebx")) || disassembly[i + 1].opcode === "push ebp") && (disassembly[i + 1].offset & 0xF) === 0) {
                        ++i; // Push the cursor back onto the function boundary.
                        break;
                    }
                }

                if (i < 0) {
                    process.stderr.write("Warning: Failed to find start of function containing " + result.offset + " '" + str + "'\n");
                    continue;
                }

                const func = await processFunction(r2, binaryInfo.baddr, disassembly[i].offset, str, result.offset);
                if (!func) {
                    continue;
                }

                output.push(func);

                //console.log(disassembly[i]);

                //break;
            }
        }
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
        return i <= 0 || d.offset != a[i - 1].offset;
    });

    // TODO: Scan for vprof names that look like they've been inlined (duplicates)

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
