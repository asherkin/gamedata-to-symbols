// vim: set background=light:

const fs = require('fs');
const path = require('path');
const util = require('util');
const r2promise = require('r2pipe-promise');

const smc = require('./smc-parser');

const exec = util.promisify(require('child_process').exec);

/*
const gameDataFile = './game.csgo.txt';
const gameDataPlatform = 'linux';
const binaryFile = './server.so';
*/

const gameDataFile = './game.csgo.txt';
const gameDataPlatform = 'windows';
const binaryFile = './server.dll';

(async function() {
    const gameDataText = await util.promisify(fs.readFile)(gameDataFile, 'utf8');
    const gameData = smc.parse(gameDataText);
    //console.log(JSON.stringify(gameData, null, 2));

    const functions = {};

    for (let rootIndex = 0; rootIndex < gameData.length; ++rootIndex) {
        const root = gameData[rootIndex];

        if (root.key != 'Games') {
            continue;
        }

        const sections = root.value;

        for (let sectionIndex = 0; sectionIndex < sections.length; ++sectionIndex) {
            const section = sections[sectionIndex];

            // TODO: Check section.key for supported games.

            const blocks = section.value;

            let skipSection = false;
            const innerFunctions = {};

            for (let blockIndex = 0; blockIndex < blocks.length; ++blockIndex) {
                const block = blocks[blockIndex];

                if (block.key === '#supported') {
                    // TODO: Check supported games.
                } else if (block.key === 'Signatures') {
                    const signatures = block.value;

                    for (let signatureIndex = 0; signatureIndex < signatures.length; ++signatureIndex) {
                        const signature = signatures[signatureIndex];

                        const platforms = signature.value;

                        for (let platformIndex = 0; platformIndex < platforms.length; ++platformIndex) {
                            const platform = platforms[platformIndex];

                            if (platform.key !== gameDataPlatform) {
                                continue;
                            }

                            const key = path.basename(gameDataFile, '.txt') + '::' + signature.key;
                            const radareSignature = platform.value.replace(/\\x2A/gi, '..').replace(/\\x([0-9A-F]{2})/gi, '$1');
                            innerFunctions[key] = radareSignature;
                        }
                    }
                }
            }

            if (!skipSection) {
                for (const func in innerFunctions) {
                    if (!innerFunctions.hasOwnProperty(func)) {
                        continue;
                    }

                    functions[func] = innerFunctions[func];
                }
            }
        }
    }

    // console.log(JSON.stringify(functions, null, 2));

    const output = [];

    if (binaryFile.match(/\.so$/i)) {
        const identifier = (await exec('../bin/breakpad_moduleid ' + binaryFile)).stdout.trim();
        output.push(util.format('MODULE Linux x86 %s %s', identifier, path.basename(binaryFile)));
    } else if (binaryFile.match(/\.dll$/i)) {
        const debugInfo = (await exec('objdump -p ' + binaryFile + ' | grep -A1 CodeView | tail -n 1')).stdout.trim().match(/\(format [^ ]+ signature ([^ ]+) age ([^ ]+)\)/);
        const identifier = debugInfo[1].toUpperCase() + (+debugInfo[2]).toString(16).toLowerCase();
        output.push(util.format('MODULE windows x86 %s %s', identifier, path.basename(binaryFile).replace(/\.dll$/i, '.pdb')));
    }

    const r2 = await r2promise.open(binaryFile);

    const binaryInfo  = await r2.cmdj('iIj');

    for (const func in functions) {
        if (!functions.hasOwnProperty(func)) {
            continue;
        }

        const search = await r2.cmdj('/xj ' + functions[func]);
        // console.log(search);

        if (search.length === 0) {
            // console.log('no match found for ' + func);
            continue;
        } else if (search.length > 1) {
            // console.log(search.length + ' matches found for ' + func);
        }

        const analyze = await r2.cmd('af ' + func + ' ' + search[0].offset);

        const info = (await r2.cmdj('afij ' + search[0].offset))[0];
        // console.log(info);

        let paramSize = 0;
        for (let i = 0; i < info.bpvars.length; ++i) {
            if (info.bpvars[i].kind !== 'arg') {
                continue;
            }
            if (info.bpvars[i].type !== 'int') {
                throw new Error('unknown bpvar arg type');
            }
            paramSize += 4;
        }
        for (let i = 0; i < info.spvars.length; ++i) {
            if (info.spvars[i].kind !== 'arg') {
                continue;
            }
            if (info.spvars[i].type !== 'int') {
                throw new Error('unknown spvar arg type');
            }
            paramSize += 4;
        }

        output.push(util.format('FUNC %s %s %s %s', (info.offset - binaryInfo.baddr).toString(16), info.size.toString(16), paramSize.toString(16), func));
    }    

    // console.log(JSON.stringify(output, null, 2));
    console.log(output.join('\n'));

    r2.quit();
})();
