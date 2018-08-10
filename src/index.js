/**
 * PDF Validator module
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module pdfvalidator
 */
import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import * as pdfjs from './pdf.js';
import * as eslutils from 'eslutils';
import './webcrypto';

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

let PDFJS;
if(typeof window === 'undefined')
  PDFJS = pdfjs.PDFJS;
else
  PDFJS = window.PDFJS;

/**
 * Get all signatures from a PDFDocument.
 * @param {pdfjs.PDFJS.PDFDocument} pdf - The PDF document
 * @return {Array<PDFSignature>} An array of PDFSignature objects describing
 * all signatures found.
 */
function getSignatures(pdf) {
  const acroForm = pdf.xref.root.get('AcroForm');
  if(typeof acroForm === 'undefined')
    return [];

  const sigs = [];
  const fields = acroForm.get('Fields');
  fields.forEach(field => {
    if(PDFJS.isRef(field) === false)
      return;

    const sigField = pdf.xref.fetch(field);
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
    const cmsSignedSimp = new pkijs.SignedData({
      schema: cmsContentSimp.content
    });

    sigs.push({
      cmsSignedSimp,
      ranges: [
        {
          start: byteRange[0],
          end: byteRange[0] + byteRange[1]
        },
        {
          start: byteRange[2],
          end: byteRange[2] + byteRange[3]
        }
      ]
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
 * @return {Promise<boolean>} A promise that resolves to true if the hash is
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
function validateSignature(signature, contents, trustedSigningCAs,
  trustedTimestampingCAs, id) {
  let sequence = Promise.resolve();
  const sigInfo = new eslutils.SignatureInfo(id);

  let signedDataLen = 0;
  signature.ranges.forEach(range => {
    signedDataLen += (range.end - range.start);
  });
  const signedData = new ArrayBuffer(signedDataLen);
  const signedDataView = new Uint8Array(signedData);
  const contentsView = new Uint8Array(contents);

  let count = 0;
  signature.ranges.forEach(range => {
    for(let i = range.start; i < range.end; i++, count++)
      signedDataView[count] = contentsView[i];
  });

  sequence = sequence.then(() => signature.cmsSignedSimp.verify({
    signer: 0,
    data: signedData,
    checkChain: false,
    extendedMode: true
  })).then(result => {
    sigInfo.sigVerified = result.signatureVerified;
    sigInfo.cert = result.signerCertificate;
  }, result => {
    sigInfo.sigVerified = false;
    sigInfo.cert = result.signerCertificate;
  });

  trustedSigningCAs.forEach(truststore => {
    sequence = sequence.then(() => eslutils.verifyChain(sigInfo.cert,
      signature.cmsSignedSimp.certificates, truststore.certificates)
    ).then(result => {
      sigInfo.signerVerified.push({
        name: truststore.name,
        status: result
      });
    });
  });

  const hashAlgo = pkijs.getAlgorithmByOID(
    signature.cmsSignedSimp.signerInfos[0].digestAlgorithm.algorithmId);
  if('name' in hashAlgo)
    sigInfo.hashAlgorithm = hashAlgo.name;

  if('signedAttrs' in signature.cmsSignedSimp.signerInfos[0]) {
    sequence = sequence.then(() => {
      return verifyCMSHash(signature.cmsSignedSimp, signedData);
    }).then((result) => {
      sigInfo.hashVerified = result;
    });

    if('unsignedAttrs' in signature.cmsSignedSimp.signerInfos[0]) {
      const tsToken = extractTSToken(signature.cmsSignedSimp);

      if(tsToken != null) {
        sigInfo.hasTS = true;

        const tsSigned = new pkijs.SignedData({ schema: tsToken.content });

        sequence = sequence.then(() => tsSigned.verify({
          signer: 0,
          data: signature.cmsSignedSimp.signerInfos[0].signature.valueBlock
            .valueHex,
          checkChain: false,
          extendedMode: true
        })).then(result => {
          sigInfo.tsVerified = result.signatureVerified;
          sigInfo.tsCert = result.signerCertificate;
        }, result => {
          sigInfo.tsVerified = false;
          sigInfo.tsCert = result.signerCertificate;
        });

        trustedTimestampingCAs.forEach(truststore => {
          sequence = sequence.then(() => eslutils.verifyChain(sigInfo.tsCert,
            tsSigned.certificates, truststore.certificates)
          ).then(result => {
            sigInfo.tsCertVerified.push({
              name: truststore.name,
              status: result
            });
          });
        });
      }
    }
  } else {
    /*
     * If there are no signed attributes, and the hash is computed just from
     * the original document, then we assume the signer calculated the correct
     * hash if the signature is correct.
     */
    sequence = sequence.then(() => {
      sigInfo.hashVerified = sigInfo.sigVerified;
    });
  }

  return sequence.then(() => sigInfo);
}

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

    const bufferView = new Uint8Array(buffer);

    const pdf = new PDFJS.PDFDocument(null, bufferView, null);

    try {
      pdf.parseStartXRef();
      pdf.parse();
    } catch(ex) {
      return;
    }

    this.validationInfo.isValid = true;

    try {
      this.pdfSignatures = getSignatures(pdf);
    } catch(e) {
      this.pdfSignatures = [];
    }

    if(this.pdfSignatures.length > 0)
      this.validationInfo.isSigned = true;
  }

  /**
   * Add a trust store to the document signing trust stores.
   * @param {TrustStore} truststore - The trust store to add.
   */
  addSigningTruststore(truststore) {
    this.trustedSigningCAs.addTrustStore(truststore);
  }

  /**
   * Remove a trust store from the document signing trust stores by name.
   * @param {string} name - The name of the trust store to remove.
   */
  removeSigningTruststore(name) {
    this.trustedSigningCAs.removeTrustStore(name);
  }

  /**
   * Add a trust store to the timestamping trust stores.
   * @param {TrustStore} truststore - The trust store to add.
   */
  addTimestampingTruststore(truststore) {
    this.trustedTimestampingCAs.addTrustStore(truststore);
  }

  /**
   * Remove a trust store from the document signing trust stores by name.
   * @param {string} name - The name of the trust store to remove.
   */
  removeTimestampingTruststore(name) {
    this.trustedTimestampingCAs.removeTrustStore(name);
  }

  /**
   * Validate the PDF file.
   * @return {Promise<PDFInfo>} A promise that is resolved with a PDFInfo
   * object containing the validation results.
   */
  validate() {
    let sequence = Promise.resolve();

    if((this.validationInfo.isValid === false) ||
      (this.validationInfo.isSigned === false))
      return sequence.then(() => { return this.validationInfo; });

    for(let i = 0; i < this.pdfSignatures.length; i++) {
      sequence = sequence.then(() => validateSignature(this.pdfSignatures[i],
        this.buffer, this.trustedSigningCAs, this.trustedTimestampingCAs, i))
        .then(result => {
          this.validationInfo.signatures.push(result);
        });
    }

    return sequence.then(() => this.validationInfo);
  }
}
