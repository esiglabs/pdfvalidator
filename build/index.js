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

require('./webcrypto');

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/**
  * A trust store.
  * @typedef {Object} TrustStore
  * @property {string} name - The name of the trust store.
  * @property {Array<pkijs.Certificate>} certificates - All the certificates
  * contained in the trust store.
  */

/**
 * Trust store verification status.
 * @typedef {Object} TrustStoreStatus
 * @property {string} name - The name of the trust store.
 * @property {boolean} status - True if the certificate chains to this trust
 * store, false otherwise.
 */

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
 * @return {Promise<boolean>} A promise that resolves to true if the hash is
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
 * @param {Array<pkijs.Certificate>} chain - Additional certificates in the
 * chain.
 * @param {Array<pkijs.Certificate>} trustedCAs - The trusted CAs
 * @return {Promise<boolean>} A promise that is resolved with a boolean value
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
     * @type {Array<TrustStoreStatus>}
     * @description Signer certificate chains to a trusted signing CA.
     */
    this.signerVerified = [];
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
     * @type {Array<TrustStoreStatus>}
     * @description The certificate of the timestamp chains to a trusted
     * timestamping CA.
     */
    this.tsCertVerified = [];
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
    key: 'isSignersVerified',


    /**
     * Check if the signer has been verified against a truststore. If the file is
     * timestamped, then the timestamp signer will also be checked against another
     * truststore.
     * @param {string} signingTruststore - The name of the signing truststore.
     * @param {string} timestampingTruststore - The name of the timestamping
     * truststore.
     * @return {boolean} True if the file was verified against both truststores,
     * false otherwise.
     */
    value: function isSignersVerified(signingTruststore, timestampingTruststore) {
      if (!this.isValid || !this.isSigned) return false;

      var verified = false;
      this.signerVerified.forEach(function (signer) {
        if (signer.name === signingTruststore) verified = signer.status;
      });
      if (verified === false) return false;

      if (this.hasTS) {
        verified = false;
        this.tsCertVerified.forEach(function (signer) {
          if (signer.name === timestampingTruststore) verified = signer.status;
        });
        if (verified === false) return false;
      }

      return true;
    }
  }, {
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
   * @param {ArrayBuffer} buffer - The buffer containing the PDF file.
   */
  function PDFValidator(buffer) {
    _classCallCheck(this, PDFValidator);

    /**
     * @type {Array<TrustStore>}
     * @description Trusted document signing CAs.
     */
    this.trustedSigningCAs = [];
    /**
     * @type {Array<TrustStore>}
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

    var bufferView = new Uint8Array(buffer);

    var pdf = new pdfjs.PDFJS.PDFDocument(null, bufferView, null);

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
      signedDataView[count] = bufferView[_i];
    }for (var j = byteRange[2]; j < byteRange[2] + byteRange[3]; j++, count++) {
      signedDataView[count] = bufferView[j];
    }this.pdfInfo.isSigned = true;
  }

  /**
   * Add a trust store to the document signing trust stores.
   * @param {TrustStore} truststore - The trust store to add.
   */


  _createClass(PDFValidator, [{
    key: 'addSigningTruststore',
    value: function addSigningTruststore(truststore) {
      this.trustedSigningCAs.push(truststore);
    }

    /**
     * Remove a trust store from the document signing trust stores by name.
     * @param {string} name - The name of the trust store to remove.
     */

  }, {
    key: 'removeSigningTruststore',
    value: function removeSigningTruststore(name) {
      var idx = void 0;

      for (idx = 0; idx < this.trustedSigningCAs.length; idx++) {
        if (this.trustedSigningCAs[idx].name === name) {
          this.trustedSigningCAs.splice(idx, 1);
          idx--;
        }
      }
    }

    /**
     * Add a trust store to the timestamping trust stores.
     * @param {TrustStore} truststore - The trust store to add.
     */

  }, {
    key: 'addTimestampingTruststore',
    value: function addTimestampingTruststore(truststore) {
      this.trustedTimestampingCAs.push(truststore);
    }

    /**
     * Remove a trust store from the document signing trust stores by name.
     * @param {string} name - The name of the trust store to remove.
     */

  }, {
    key: 'removeTimestampingTruststore',
    value: function removeTimestampingTruststore(name) {
      var idx = void 0;

      for (idx = 0; idx < this.trustedTimestampingCAs.length; idx++) {
        if (this.trustedTimestampingCAs[idx].name === name) {
          this.trustedTimestampingCAs.splice(idx, 1);
          idx--;
        }
      }
    }

    /**
     * Validate the PDF file.
     * @return {Promise<PDFInfo>} A promise that is resolved with a PDFInfo
     * object containing the validation results.
     */

  }, {
    key: 'validate',
    value: function validate() {
      var _this = this;

      var sequence = Promise.resolve();

      if (this.pdfInfo.isValid === false || this.pdfInfo.isSigned === false) return sequence.then(function () {
        return _this.pdfInfo;
      });

      sequence = sequence.then(function () {
        return _this.cmsSignedSimp.verify({
          signer: 0,
          data: _this.signedDataBuffer,
          checkChain: false,
          extendedMode: true
        });
      }).then(function (result) {
        _this.pdfInfo.sigVerified = result.signatureVerified;
        _this.pdfInfo.cert = result.signerCertificate;
      }, function (result) {
        _this.pdfInfo.sigVerified = false;
        _this.pdfInfo.cert = result.signerCertificate;
      });

      this.trustedSigningCAs.forEach(function (truststore) {
        sequence = sequence.then(function () {
          return verifyChain(_this.pdfInfo.cert, _this.cmsSignedSimp.certificates, truststore.certificates);
        }).then(function (result) {
          _this.pdfInfo.signerVerified.push({
            name: truststore.name,
            status: result
          });
        });
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
                checkChain: false,
                extendedMode: true
              });
            }).then(function (result) {
              _this.pdfInfo.tsVerified = result.signatureVerified;
              _this.pdfInfo.tsCert = result.signerCertificate;
            }, function (result) {
              _this.pdfInfo.tsVerified = false;
              _this.pdfInfo.tsCert = result.signerCertificate;
            });

            this.trustedTimestampingCAs.forEach(function (truststore) {
              sequence = sequence.then(function () {
                return verifyChain(_this.pdfInfo.tsCert, tsSigned.certificates, truststore.certificates);
              }).then(function (result) {
                _this.pdfInfo.tsCertVerified.push({
                  name: truststore.name,
                  status: result
                });
              });
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