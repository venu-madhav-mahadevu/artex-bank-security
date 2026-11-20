// A5 XXE — disable DTDs, external entities, and network access in the parser.
const libxml = require('libxmljs2');
function parseXmlSafely(xml) {
  return libxml.parseXml(xml, { noent: false, dtdload: false, dtdvalid: false, nonet: true });
}
module.exports = { parseXmlSafely };
