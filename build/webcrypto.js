'use strict';

var _pkijs = require('pkijs');

var pkijs = _interopRequireWildcard(_pkijs);

var _nodeWebcryptoOssl = require('node-webcrypto-ossl');

var _nodeWebcryptoOssl2 = _interopRequireDefault(_nodeWebcryptoOssl);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

/* Use openssl webcrypto polyfill for node */
/**
 * PDF Validator module
 * Webcrypto polyfill loader.
 *
 * By Fotis Loukos <me@fotisl.com>
 */
var webcrypto = new _nodeWebcryptoOssl2.default();
pkijs.setEngine('OpenSSL', webcrypto, webcrypto.subtle);
//# sourceMappingURL=webcrypto.js.map