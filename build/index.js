'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.PDFValidator = undefined;

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

var _eslutils = require('eslutils');

var eslutils = _interopRequireWildcard(_eslutils);

require('./webcrypto');

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/**
 * A range in the file.
 * @typedef {Object} Range
 * @property {number} start - The start of the range.
 * @property {number} end - The end of the range.
 */

/**
 * A PDF signature.
 * @typedef {Object} PDFSignature
 * @property {pkijs.SignedData} cmsSignedSimp - A SignedData structure
 * containing the signature
 * @property {Array<Range>} ranges - An array of all ranges signed by this
 * signature.
 */

var PDFJS = void 0;
if (typeof window === 'undefined') PDFJS = pdfjs.PDFJS;else PDFJS = window.PDFJS;

/**
 * Get all signatures from a PDFDocument.
 * @param {pdfjs.PDFJS.PDFDocument} pdf - The PDF document
 * @return {Array<PDFSignature>} An array of PDFSignature objects describing
 * all signatures found.
 */
function getSignatures(pdf) {
  var acroForm = pdf.xref.root.get('AcroForm');
  if (typeof acroForm === 'undefined') return [];

  var sigs = [];
  var fields = acroForm.get('Fields');
  fields.forEach(function (field) {
    if (PDFJS.isRef(field) === false) return;

    var sigField = pdf.xref.fetch(field);
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
    var cmsSignedSimp = new pkijs.SignedData({
      schema: cmsContentSimp.content
    });

    sigs.push({
      cmsSignedSimp: cmsSignedSimp,
      ranges: [{
        start: byteRange[0],
        end: byteRange[0] + byteRange[1]
      }, {
        start: byteRange[2],
        end: byteRange[2] + byteRange[3]
      }]
    });
  });

  return sigs;
}

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
 * Validate a single signature.
 * @param {PDFSignature} signature - The PDF signature.
 * @param {ArrayBuffer} contents - The contents of the file.
 * @param {eslutils.TrustStoreList} trustedSigningCAs - Trusted document
 * signing CAs.
 * @param {eslutils.TrustStoreList} trustedTimestampingCAs - Trusted document
 * timestamping CAs.
 * @param {number} id - The id of the signature.
 * @return {Promise<eslutils.SignatureInfo>} A promise that is resolved with
 * a SignatureInfo object containing information about the signature.
 */
function validateSignature(signature, contents, trustedSigningCAs, trustedTimestampingCAs, id) {
  var sequence = Promise.resolve();
  var sigInfo = new eslutils.SignatureInfo(id);

  var signedDataLen = 0;
  signature.ranges.forEach(function (range) {
    signedDataLen += range.end - range.start;
  });
  var signedData = new ArrayBuffer(signedDataLen);
  var signedDataView = new Uint8Array(signedData);
  var contentsView = new Uint8Array(contents);

  var count = 0;
  signature.ranges.forEach(function (range) {
    for (var i = range.start; i < range.end; i++, count++) {
      signedDataView[count] = contentsView[i];
    }
  });

  sequence = sequence.then(function () {
    return signature.cmsSignedSimp.verify({
      signer: 0,
      data: signedData,
      checkChain: false,
      extendedMode: true
    });
  }).then(function (result) {
    sigInfo.sigVerified = result.signatureVerified;
    sigInfo.cert = result.signerCertificate;
  }, function (result) {
    sigInfo.sigVerified = false;
    sigInfo.cert = result.signerCertificate;
  });

  trustedSigningCAs.forEach(function (truststore) {
    sequence = sequence.then(function () {
      return eslutils.verifyChain(sigInfo.cert, signature.cmsSignedSimp.certificates, truststore.certificates);
    }).then(function (result) {
      sigInfo.signerVerified.push({
        name: truststore.name,
        status: result
      });
    });
  });

  if ('signedAttrs' in signature.cmsSignedSimp.signerInfos[0]) {
    var hashAlgo = pkijs.getAlgorithmByOID(signature.cmsSignedSimp.signerInfos[0].digestAlgorithm.algorithmId);
    if ('name' in hashAlgo) sigInfo.hashAlgorithm = hashAlgo.name;

    sequence = sequence.then(function () {
      return verifyCMSHash(signature.cmsSignedSimp, signedData);
    }).then(function (result) {
      sigInfo.hashVerified = result;
    });

    if ('unsignedAttrs' in signature.cmsSignedSimp.signerInfos[0]) {
      var tsToken = extractTSToken(signature.cmsSignedSimp);

      if (tsToken != null) {
        sigInfo.hasTS = true;

        var tsSigned = new pkijs.SignedData({ schema: tsToken.content });

        sequence = sequence.then(function () {
          return tsSigned.verify({
            signer: 0,
            data: signature.cmsSignedSimp.signerInfos[0].signature.valueBlock.valueHex,
            checkChain: false,
            extendedMode: true
          });
        }).then(function (result) {
          sigInfo.tsVerified = result.signatureVerified;
          sigInfo.tsCert = result.signerCertificate;
        }, function (result) {
          sigInfo.tsVerified = false;
          sigInfo.tsCert = result.signerCertificate;
        });

        trustedTimestampingCAs.forEach(function (truststore) {
          sequence = sequence.then(function () {
            return eslutils.verifyChain(sigInfo.tsCert, tsSigned.certificates, truststore.certificates);
          }).then(function (result) {
            sigInfo.tsCertVerified.push({
              name: truststore.name,
              status: result
            });
          });
        });
      }
    }
  }

  return sequence.then(function () {
    return sigInfo;
  });
}

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
     * @type {eslutils.TrustStoreList}
     * @description Trusted document signing CAs.
     */
    this.trustedSigningCAs = new eslutils.TrustStoreList();
    /**
     * @type {eslutils.TrustStoreList}
     * @description Trusted document timestamping CAs.
     */
    this.trustedTimestampingCAs = new eslutils.TrustStoreList();
    /**
     * @type {eslutils.ValidationInfo}
     * @description A ValidationInfo object holding the validation results.
     */
    this.validationInfo = new eslutils.ValidationInfo();
    /**
     * @type {ArrayBuffer}
     * @description The contents of the file.
     */
    this.buffer = buffer;
    /**
     * @type {Array<PDFSignature>}
     * @description The signatures in the file.
     */
    this.pdfSignatures = null;

    var bufferView = new Uint8Array(buffer);

    var pdf = new PDFJS.PDFDocument(null, bufferView, null);

    try {
      pdf.parseStartXRef();
      pdf.parse();
    } catch (ex) {
      return;
    }

    this.validationInfo.isValid = true;

    try {
      this.pdfSignatures = getSignatures(pdf);
    } catch (e) {
      this.pdfSignatures = [];
    }

    if (this.pdfSignatures.length > 0) this.validationInfo.isSigned = true;
  }

  /**
   * Add a trust store to the document signing trust stores.
   * @param {TrustStore} truststore - The trust store to add.
   */


  _createClass(PDFValidator, [{
    key: 'addSigningTruststore',
    value: function addSigningTruststore(truststore) {
      this.trustedSigningCAs.addTrustStore(truststore);
    }

    /**
     * Remove a trust store from the document signing trust stores by name.
     * @param {string} name - The name of the trust store to remove.
     */

  }, {
    key: 'removeSigningTruststore',
    value: function removeSigningTruststore(name) {
      this.trustedSigningCAs.removeTrustStore(name);
    }

    /**
     * Add a trust store to the timestamping trust stores.
     * @param {TrustStore} truststore - The trust store to add.
     */

  }, {
    key: 'addTimestampingTruststore',
    value: function addTimestampingTruststore(truststore) {
      this.trustedTimestampingCAs.addTrustStore(truststore);
    }

    /**
     * Remove a trust store from the document signing trust stores by name.
     * @param {string} name - The name of the trust store to remove.
     */

  }, {
    key: 'removeTimestampingTruststore',
    value: function removeTimestampingTruststore(name) {
      this.trustedTimestampingCAs.removeTrustStore(name);
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

      if (this.validationInfo.isValid === false || this.validationInfo.isSigned === false) return sequence.then(function () {
        return _this.validationInfo;
      });

      var _loop = function _loop(i) {
        sequence = sequence.then(function () {
          return validateSignature(_this.pdfSignatures[i], _this.buffer, _this.trustedSigningCAs, _this.trustedTimestampingCAs, i);
        }).then(function (result) {
          _this.validationInfo.signatures.push(result);
        });
      };

      for (var i = 0; i < this.pdfSignatures.length; i++) {
        _loop(i);
      }

      return sequence.then(function () {
        return _this.validationInfo;
      });
    }
  }]);

  return PDFValidator;
}();
//# sourceMappingURL=index.js.map