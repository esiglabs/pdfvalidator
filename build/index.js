'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.PDFValidator = exports.PDFInfo = undefined;

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }(); /**
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      * PDF Validator module
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      *
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      * By Fotis Loukos <me@fotisl.com>
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      * @module pdfvalidator
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      */


var _pkijs = require('pkijs');

var pkijs = _interopRequireWildcard(_pkijs);

var _asn1js = require('asn1js');

var asn1js = _interopRequireWildcard(_asn1js);

var _pdf = require('./pdf.js');

var pdfjs = _interopRequireWildcard(_pdf);

var _nodeWebcryptoOssl = require('node-webcrypto-ossl');

var _nodeWebcryptoOssl2 = _interopRequireDefault(_nodeWebcryptoOssl);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/* Use openssl webcrypto polyfill for node */
var webcrypto = new _nodeWebcryptoOssl2.default();
pkijs.setEngine('OpenSSL', webcrypto, webcrypto.subtle);

/**
 * Extract the timestamp token from the unsigned attributes of the CMS
 * signed data.
 * @param {pkijs.SignedData} cmsSignedSimp - The CMS signed data.
 * @return {pkijs.ContentInfo} The timestamp token as a pkijs.ContentInfo
 * object or null if no timestamp is present.
 */
function extractTSToken(cmsSignedSimp) {
  if (cmsSignedSimp === null) return null;

  if (!('unsignedAttrs' in cmsSignedSimp.signerInfos[0])) return null;

  var tsattr = null;

  cmsSignedSimp.signerInfos[0].unsignedAttrs.attributes.forEach(function (attr) {
    if (attr.type === '1.2.840.113549.1.9.16.2.14') tsattr = attr;
  });

  if (tsattr === null) return null;

  var tstoken = null;

  try {
    var asn1 = asn1js.fromBER(tsattr.values[0].valueBeforeDecode);
    tstoken = new pkijs.ContentInfo({ schema: asn1.result });
  } catch (ex) {}

  return tstoken;
}

/**
 * Verify the hash of a some CMS signed data.
 * @param {pkijs.SignedData} cmsSignedSimp - The CMS Signed Data structure
 * @param {ArrayBuffer} signedDataBuffer - The signed data.
 * @return {Promise.<boolean>} A promise that resolves to true if the hash is
 * correct, otherwise false.
 */
function verifyCMSHash(cmsSignedSimp, signedDataBuffer) {
  if (cmsSignedSimp === null || signedDataBuffer === null) return Promise.resolve(false);

  var hashAlgo = pkijs.getAlgorithmByOID(cmsSignedSimp.signerInfos[0].digestAlgorithm.algorithmId);
  if (!('name' in hashAlgo)) return Promise.resolve(false);

  return Promise.resolve().then(function () {
    var crypto = pkijs.getCrypto();

    return crypto.digest({ name: hashAlgo.name }, new Uint8Array(signedDataBuffer));
  }).then(function (result) {
    var messageDigest = new ArrayBuffer(0);
    var signedAttrs = cmsSignedSimp.signerInfos[0].signedAttrs;

    // Find messageDigest attribute
    for (var j = 0; j < signedAttrs.attributes.length; j++) {
      if (signedAttrs.attributes[j].type === '1.2.840.113549.1.9.4') {
        messageDigest = signedAttrs.attributes[j].values[0].valueBlock.valueHex;
        break;
      }
    }

    if (messageDigest.byteLength === 0) return false;

    var view1 = new Uint8Array(messageDigest);
    var view2 = new Uint8Array(result);

    if (view1.length !== view2.length) return false;

    for (var i = 0; i < view1.length; i++) {
      if (view1[i] !== view2[i]) return false;
    }

    return true;
  }, function (result) {
    return false;
  });
}

/**
 * Verify if a certificate chains to some trusted CAs.
 * @param {pkijs.Certificate} certificate - The certificate that will be
 * checked.
 * @param {Array.<pkijs.Certificate>} chain - Additional certificates in the
 * chain.
 * @param {Array.<pkijs.Certificate>} trustedCAs - The trusted CAs
 * @return {Promise.<boolean>} A promise that is resolved with a boolean value
 * stating if the certificate was verified or not.
 */
function verifyChain(certificate, chain, trustedCAs) {
  if (certificate === null) return Promise.resolve(false);

  var newChain = chain.splice();
  newChain.push(certificate);

  return Promise.resolve().then(function () {
    var certificateChainEngine = new pkijs.CertificateChainValidationEngine({
      certs: newChain,
      trustedCerts: trustedCAs
    });

    return certificateChainEngine.verify();
  }).then(function (result) {
    return result.result;
  }, function (result) {
    return false;
  });
}

/**
 * Document information definition
 */

var PDFInfo = exports.PDFInfo = function () {
  /**
   * Generate an empty PDFInfo object.
   * @constructor
   */
  function PDFInfo() {
    _classCallCheck(this, PDFInfo);

    /**
     * @type {boolean}
     * @description A valid PDF file.
     */
    this.isValid = false;
    /**
     * @type {boolean}
     * @description A signed PDF file.
     */
    this.isSigned = false;
    /**
     * @type {boolean}
     * @description Signed hash has been verified.
     */
    this.sigVerified = false;
    /**
     * @type {boolean}
     * @description The hash corresponds to the signed data.
     */
    this.hashVerified = false;
    /**
     * @type {string}
     * @description The algorithm that was used to hash the data.
     */
    this.hashAlgorithm = '';
    /**
     * @type {boolean}
     * @description Signer certificate chains to a trusted signing CA.
     */
    this.signerVerified = false;
    /**
     * @type {boolean}
     * @description A timestamped PDF file.
     */
    this.hasTS = false;
    /**
     * @type {boolean}
     * @description The timestamp has been verified.
     */
    this.tsVerified = false;
    /**
     * @type {boolean}
     * @description The certificate of the timestamp chains to a trusted
     * timestamping CA.
     */
    this.tsCertVerified = false;
    /**
     * @type {pkijs.Certificate}
     * @description The signer's certificate.
     */
    this.cert = null;
    /**
     * @type {pkijs.Certificate}
     * @description The timestamp authority's certificate.
     */
    this.tsCert = null;
  }

  /**
   * Check if the file verified was a valid signed PDF whose signature and
   * signed hash have been verified.
   */


  _createClass(PDFInfo, [{
    key: 'isValidSigned',
    get: function get() {
      return this.isValid & this.isSigned & this.sigVerified & this.hashVerified;
    }

    /**
     * Check if the file verified was a valid signed and timestamped PDF whose
     * signature, signed hash and timestamp have been verified.
     */

  }, {
    key: 'isValidSignedTimestamped',
    get: function get() {
      return this.isValid & this.isSigned & this.sigVerified & this.hashVerified & this.hasTS & this.tsVerified;
    }

    /**
     * Check if the signer has been verified. If the file is timestamped, then
     * the timestamp signer will also be checked.
     */

  }, {
    key: 'isSignersVerified',
    get: function get() {
      if (!this.isValid || !this.isSigned) return false;

      if (!this.signerVerified) return false;

      if (this.hasTS && !this.tsCertVerified) return false;

      return true;
    }
  }]);

  return PDFInfo;
}();

;

/**
 * PDF Validator class
 */

var PDFValidator = exports.PDFValidator = function () {
  /**
   * Load a PDF file from a buffer.
   * @param {Buffer} buffer - The buffer containing the PDF file.
   */
  function PDFValidator(buffer) {
    _classCallCheck(this, PDFValidator);

    /**
     * @type {Array.<pkijs.Certificate>}
     * @description Trusted document signing CAs.
     */
    this.trustedSigningCAs = [];
    /**
     * @type {Array.<pkijs.Certificate>}
     * @description Trusted document timestamping CAs.
     */
    this.trustedTimestampingCAs = [];
    /**
     * @type {pkijs.SignedData}
     * @description The SignedData structure of the PDF signature.
     */
    this.cmsSignedSimp = null;
    /**
     * @type {ArrayBuffer}
     * @description An ArrayBuffer holding the signed data.
     */
    this.signedDataBuffer = null;
    /**
     * @type {PDFInfo}
     * @description A PDFInfo object holding the validation results.
     */
    this.pdfInfo = new PDFInfo();

    var pdf = new pdfjs.PDFJS.PDFDocument(null, new Uint8Array(buffer), null);

    try {
      pdf.parseStartXRef();
      pdf.parse();
    } catch (ex) {
      return;
    }

    this.pdfInfo.isValid = true;

    var acroForm = pdf.xref.root.get('AcroForm');
    if (typeof acroForm === 'undefined') return;

    var fields = acroForm.get('Fields');
    if (pdfjs.PDFJS.isRef(fields[0]) === false) return;

    var sigField = pdf.xref.fetch(fields[0]);
    var sigFieldType = sigField.get('FT');
    if (typeof sigFieldType === 'undefined' || sigFieldType.name !== 'Sig') return;

    var v = sigField.get('V');
    var byteRange = v.get('ByteRange');
    var contents = v.get('Contents');

    var contentLength = contents.length;
    var contentBuffer = new ArrayBuffer(contentLength);
    var contentView = new Uint8Array(contentBuffer);

    for (var i = 0; i < contentLength; i++) {
      contentView[i] = contents.charCodeAt(i);
    }var asn1 = asn1js.fromBER(contentBuffer);

    var cmsContentSimp = new pkijs.ContentInfo({ schema: asn1.result });
    this.cmsSignedSimp = new pkijs.SignedData({
      schema: cmsContentSimp.content
    });

    this.signedDataBuffer = new ArrayBuffer(byteRange[1] + byteRange[3]);
    var signedDataView = new Uint8Array(this.signedDataBuffer);

    var count = 0;
    for (var _i = byteRange[0]; _i < byteRange[0] + byteRange[1]; _i++, count++) {
      signedDataView[count] = buffer[_i];
    }for (var j = byteRange[2]; j < byteRange[2] + byteRange[3]; j++, count++) {
      signedDataView[count] = buffer[j];
    }this.pdfInfo.isSigned = true;
  }

  /**
   * Add certificates to the trusted signing certificates bundle.
   * @param {Array.<pkijs.Certificate>} certificates - An array of the
   * certificates to add.
   */


  _createClass(PDFValidator, [{
    key: 'addTrustedSigningCAs',
    value: function addTrustedSigningCAs(certificates) {
      if (!(certificates instanceof Array)) return;

      this.trustedSigningCAs = this.trustedSigningCAs.concat(certificates);
    }

    /**
     * Add certificates to the trusted timestamping certificates bundle.
     * @param {Array.<pkijs.Certificate>} certificates - An array of the
     * certificates to add.
     */

  }, {
    key: 'addTrustedTimestampingCAs',
    value: function addTrustedTimestampingCAs(certificates) {
      if (!(certificates instanceof Array)) return;

      this.trustedTimestampingCAs = this.trustedTimestampingCAs.concat(certificates);
    }

    /**
     * Validate the PDF file.
     * @return {Promise.<PDFInfo>} A promise that is resolved with a PDFInfo
     * object containing the validation results.
     */

  }, {
    key: 'validateDoc',
    value: function validateDoc() {
      var _this = this;

      var sequence = Promise.resolve();

      if (this.pdfInfo.isValid === false || this.pdfInfo.isSigned === false) return sequence.then(function () {
        return _this.pdfInfo;
      });

      sequence = sequence.then(function () {
        return _this.cmsSignedSimp.verify({
          signer: 0,
          data: _this.signedDataBuffer,
          trustedCerts: _this.trustedSigningCAs,
          checkChain: false,
          extendedMode: true
        });
      }).then(function (result) {
        _this.pdfInfo.sigVerified = result.signatureVerified;
        _this.pdfInfo.cert = result.signerCertificate;
      }, function (result) {
        _this.pdfInfo.sigVerified = false;
        _this.pdfInfo.cert = result.signerCertificate;
      }).then(function () {
        return verifyChain(_this.pdfInfo.cert, _this.cmsSignedSimp.certificates, _this.trustedSigningCAs);
      }).then(function (result) {
        _this.pdfInfo.signerVerified = result;
      });

      if ('signedAttrs' in this.cmsSignedSimp.signerInfos[0]) {
        var hashAlgo = pkijs.getAlgorithmByOID(this.cmsSignedSimp.signerInfos[0].digestAlgorithm.algorithmId);
        if ('name' in hashAlgo) this.pdfInfo.hashAlgorithm = hashAlgo.name;

        sequence = sequence.then(function () {
          return verifyCMSHash(_this.cmsSignedSimp, _this.signedDataBuffer);
        }).then(function (result) {
          _this.pdfInfo.hashVerified = result;
        });

        if ('unsignedAttrs' in this.cmsSignedSimp.signerInfos[0]) {
          var tsToken = extractTSToken(this.cmsSignedSimp);

          if (tsToken != null) {
            this.pdfInfo.hasTS = true;

            var tsSigned = new pkijs.SignedData({ schema: tsToken.content });

            sequence = sequence.then(function () {
              return tsSigned.verify({
                signer: 0,
                data: _this.cmsSignedSimp.signerInfos[0].signature.valueBlock.valueHex,
                trustedCerts: _this.trustedTimestampingCAs,
                checkChain: false,
                extendedMode: true
              });
            }).then(function (result) {
              _this.pdfInfo.tsVerified = result.signatureVerified;
              _this.pdfInfo.tsCert = result.signerCertificate;
            }, function (result) {
              _this.pdfInfo.tsVerified = false;
              _this.pdfInfo.tsCert = result.signerCertificate;
            }).then(function () {
              return verifyChain(_this.pdfInfo.tsCert, tsSigned.certificates, _this.trustedTimestampingCAs);
            }).then(function (result) {
              _this.pdfInfo.tsCertVerified = result;
            });
          }
        }
      }

      return sequence.then(function () {
        return _this.pdfInfo;
      });
    }
  }]);

  return PDFValidator;
}();
//# sourceMappingURL=index.js.map