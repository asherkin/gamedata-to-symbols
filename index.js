// vim: set background=light:

const fs = require('fs');
const util = require('util');
const vdf = require('@node-steam/vdf');
const r2promise = require('r2pipe-promise');

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
    const gameDataNoComments = gameDataText.replace(/(\/\*(?:(?!\*\/).|[\n\r])*\*\/)/, '');
    const gameData = vdf.parse(gameDataNoComments);
    // console.log(JSON.stringify(gameData, null, 2));

    const functions = {};

    for (const section in gameData['Games']) {
        if (!gameData['Games'].hasOwnProperty(section)) {
            continue;
        }

        if (!gameData['Games'][section].hasOwnProperty('Signatures')) {
            continue;
        }

        for (const func in gameData['Games'][section]['Signatures']) {
            if (!gameData['Games'][section]['Signatures'].hasOwnProperty(func)) {
                continue;
            }

            if (!gameData['Games'][section]['Signatures'][func].hasOwnProperty(gameDataPlatform)) {
                continue;
            }

            const signature = gameData['Games'][section]['Signatures'][func][gameDataPlatform];
            const radareSignature = signature.replace(/2A/g, '..').replace(/\\x/g, '');
            functions[func] = radareSignature;
        }
    }

    console.log(JSON.stringify(functions, null, 2));

    const r2 = await r2promise.open(binaryFile);

    const output = [];

    for (const func in functions) {
        if (!functions.hasOwnProperty(func)) {
            continue;
        }

        const search = await r2.cmdj('/xj ' + functions[func]);
        // console.log(search);

        if (search.length === 0) {
            console.log('no match found for ' + func);
            continue;
        } else if (search.length > 1) {
            console.log(search.length + ' matches found for ' + func);
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

        output.push(util.format('FUNC %s %s %s %s', info.offset.toString(16), info.size.toString(16), paramSize.toString(16), func));
    }    

    console.log(JSON.stringify(output, null, 2));

    r2.quit();
})();
