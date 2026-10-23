const fs = require('fs');
const json = JSON.stringify(JSON.parse(fs.readFileSync('clave.json', 'utf8')));
fs.writeFileSync('.dev.vars', "GOOGLE_SA_JSON='" + json + "'\n");