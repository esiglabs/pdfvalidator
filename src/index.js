/**
 * PDF Validator module
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module pdfvalidator
 */
import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import * as pdfjs from './pdf.js';
import WebCrypto from 'node-webcrypto-ossl';

/* Use openssl webcrypto polyfill for node */
const webcrypto = new WebCrypto();
pkijs.setEngine('OpenSSL', webcrypto, webcrypto.subtle);

/**
 * Extract the timestamp token from the unsigned attributes of the CMS
 * signed data.
 * @param {pkijs.SignedData} cmsSignedSimp - The CMS signed data.
 * @return {pkijs.ContentInfo} The timestamp token as a pkijs.ContentInfo
 * object or null if no timestamp is present.
 */
function extractTSToken(cmsSignedSimp) {
  if(cmsSignedSimp === null)
    return null;

  if(!('unsignedAttrs' in cmsSignedSimp.signerInfos[0]))
    return null;

  let tsattr = null;

  cmsSignedSimp.signerInfos[0].unsignedAttrs.attributes.forEach(attr => {
    if(attr.type === '1.2.840.113549.1.9.16.2.14')
      tsattr = attr;
  });

  if(tsattr === null)
    return null;

  let tstoken = null;

  try {
    let asn1 = asn1js.fromBER(tsattr.values[0].valueBeforeDecode);
    tstoken = new pkijs.ContentInfo({schema: asn1.result});
  } catch(ex) {
  }

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
  if((cmsSignedSimp === null) || (signedDataBuffer === null))
    return Promise.resolve(false);

  const hashAlgo = pkijs.getAlgorithmByOID(
    cmsSignedSimp.signerInfos[0].digestAlgorithm.algorithmId);
  if(!('name' in hashAlgo))
    return Promise.resolve(false);

  return Promise.resolve().then(() => {
    const crypto = pkijs.getCrypto();

    return crypto.digest({ name: hashAlgo.name },
      new Uint8Array(signedDataBuffer));
  }).then(result => {
    let messageDigest = new ArrayBuffer(0);
    const signedAttrs = cmsSignedSimp.signerInfos[0].signedAttrs;

    // Find messageDigest attribute
    for(let j = 0; j < signedAttrs.attributes.length; j++) {
      if(signedAttrs.attributes[j].type === '1.2.840.113549.1.9.4') {
        messageDigest = signedAttrs.attributes[j].values[0].valueBlock.valueHex;
        break;
      }
    }

    if(messageDigest.byteLength === 0)
      return false;

    const view1 = new Uint8Array(messageDigest);
    const view2 = new Uint8Array(result);

    if(view1.length !== view2.length)
      return false;

    for(let i = 0; i < view1.length; i++) {
      if(view1[i] !== view2[i])
        return false;
    }

    return true;
  }, result => {
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
  if(certificate === null)
    return Promise.resolve(false);

  const newChain = chain.splice();
  newChain.push(certificate)

  return Promise.resolve().then(() => {
    const certificateChainEngine = new pkijs.CertificateChainValidationEngine({
      certs: newChain,
      trustedCerts: trustedCAs
    });

    return certificateChainEngine.verify();
  }).then(result => {
    return result.result;
  }, result => {
    return false;
  });
}

/**
 * Document information definition
 */
export class PDFInfo {
  /**
   * Generate an empty PDFInfo object.
   * @constructor
   */
  constructor() {
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
  get isValidSigned() {
    return this.isValid & this.isSigned & this.sigVerified & this.hashVerified;
  }

  /**
   * Check if the file verified was a valid signed and timestamped PDF whose
   * signature, signed hash and timestamp have been verified.
   */
  get isValidSignedTimestamped() {
    return this.isValid & this.isSigned & this.sigVerified &
      this.hashVerified & this.hasTS & this.tsVerified;
  }

  /**
   * Check if the signer has been verified. If the file is timestamped, then
   * the timestamp signer will also be checked.
   */
  get isSignersVerified() {
    if(!this.isValid || !this.isSigned)
      return false;

    if(!this.signerVerified)
      return false;

    if(this.hasTS && !this.tsCertVerified)
      return false;

    return true;
  }
};

/**
 * PDF Validator class
 */
export class PDFValidator {
  /**
   * Load a PDF file from a buffer.
   * @param {ArrayBuffer} buffer - The buffer containing the PDF file.
   */
  constructor(buffer) {
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

    const pdf = new pdfjs.PDFJS.PDFDocument(null, new Uint8Array(buffer), null);

    try {
      pdf.parseStartXRef();
      pdf.parse();
    } catch(ex) {
      return;
    }

    this.pdfInfo.isValid = true;

    const acroForm = pdf.xref.root.get('AcroForm');
    if(typeof acroForm === 'undefined')
      return;

    const fields = acroForm.get('Fields');
    if(pdfjs.PDFJS.isRef(fields[0]) === false)
      return;

    const sigField = pdf.xref.fetch(fields[0]);
    const sigFieldType = sigField.get('FT');
    if((typeof sigFieldType === 'undefined') || (sigFieldType.name !== 'Sig'))
      return;

    const v = sigField.get('V');
    const byteRange = v.get('ByteRange');
    const contents = v.get('Contents');

    const contentLength = contents.length;
    const contentBuffer = new ArrayBuffer(contentLength);
    const contentView = new Uint8Array(contentBuffer);

    for(let i = 0; i < contentLength; i++)
      contentView[i] = contents.charCodeAt(i);

    const asn1 = asn1js.fromBER(contentBuffer);

    const cmsContentSimp = new pkijs.ContentInfo({ schema: asn1.result });
    this.cmsSignedSimp = new pkijs.SignedData({
      schema: cmsContentSimp.content
    });

    this.signedDataBuffer = new ArrayBuffer(byteRange[1] + byteRange[3]);
    const signedDataView = new Uint8Array(this.signedDataBuffer);

    let count = 0;
    for(let i = byteRange[0]; i < (byteRange[0] + byteRange[1]); i++, count++)
      signedDataView[count] = buffer[i];

    for(let j = byteRange[2]; j < (byteRange[2] + byteRange[3]); j++, count++)
      signedDataView[count] = buffer[j];

    this.pdfInfo.isSigned = true;
  }

  /**
   * Add certificates to the trusted signing certificates bundle.
   * @param {Array.<pkijs.Certificate>} certificates - An array of the
   * certificates to add.
   */
  addTrustedSigningCAs(certificates) {
    if(!(certificates instanceof Array))
      return;

    this.trustedSigningCAs = this.trustedSigningCAs.concat(certificates);
  }

  /**
   * Add certificates to the trusted timestamping certificates bundle.
   * @param {Array.<pkijs.Certificate>} certificates - An array of the
   * certificates to add.
   */
  addTrustedTimestampingCAs(certificates) {
    if(!(certificates instanceof Array))
      return;

    this.trustedTimestampingCAs = this.trustedTimestampingCAs.concat(certificates);
  }

  /**
   * Validate the PDF file.
   * @return {Promise.<PDFInfo>} A promise that is resolved with a PDFInfo
   * object containing the validation results.
   */
  validateDoc() {
    let sequence = Promise.resolve();

    if((this.pdfInfo.isValid === false) || (this.pdfInfo.isSigned === false))
      return sequence.then(() => { return this.pdfInfo; });

    sequence = sequence.then(() => this.cmsSignedSimp.verify({
      signer: 0,
      data: this.signedDataBuffer,
      trustedCerts: this.trustedSigningCAs,
      checkChain: false,
      extendedMode: true
    })).then(result => {
      this.pdfInfo.sigVerified = result.signatureVerified;
      this.pdfInfo.cert = result.signerCertificate;
    }, result => {
      this.pdfInfo.sigVerified = false;
      this.pdfInfo.cert = result.signerCertificate;
    }).then(() => verifyChain(this.pdfInfo.cert,
      this.cmsSignedSimp.certificates, this.trustedSigningCAs)
    ).then(result => {
      this.pdfInfo.signerVerified = result;
    });

    if('signedAttrs' in this.cmsSignedSimp.signerInfos[0]) {
      const hashAlgo = pkijs.getAlgorithmByOID(
        this.cmsSignedSimp.signerInfos[0].digestAlgorithm.algorithmId);
      if('name' in hashAlgo)
        this.pdfInfo.hashAlgorithm = hashAlgo.name;

      sequence = sequence.then(() => {
        return verifyCMSHash(this.cmsSignedSimp, this.signedDataBuffer);
      }).then((result) => {
        this.pdfInfo.hashVerified = result;
      });

      if('unsignedAttrs' in this.cmsSignedSimp.signerInfos[0]) {
        const tsToken = extractTSToken(this.cmsSignedSimp);

        if(tsToken != null) {
          this.pdfInfo.hasTS = true;

          const tsSigned = new pkijs.SignedData({ schema: tsToken.content });

          sequence = sequence.then(() => tsSigned.verify({
            signer: 0,
            data: this.cmsSignedSimp.signerInfos[0].signature.valueBlock
              .valueHex,
            trustedCerts: this.trustedTimestampingCAs,
            checkChain: false,
            extendedMode: true
          })).then(result => {
            this.pdfInfo.tsVerified = result.signatureVerified;
            this.pdfInfo.tsCert = result.signerCertificate;
          }, result => {
            this.pdfInfo.tsVerified = false;
            this.pdfInfo.tsCert = result.signerCertificate;
          }).then(() => {
            return verifyChain(this.pdfInfo.tsCert, tsSigned.certificates,
              this.trustedTimestampingCAs)
          }).then(result => {
            this.pdfInfo.tsCertVerified = result;
          });
        }
      }
    }

    return sequence.then(() => this.pdfInfo);
  }
}
