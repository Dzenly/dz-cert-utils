'use strict';

function getChildExecArgv() {
  // Fix for forked process debugging.
  function amIUnderDebug() {
    const argv = process.execArgv.join();
    return argv.includes('--inspect') || argv.includes('--debug');
  }

  if (!amIUnderDebug()) {
    return process.execArgv;
  }

  return process.execArgv.map((val) => {
    if (val.startsWith('--inspect-brk=')) {
      return '--inspect-brk=0';
    }
    if (val.startsWith('--inspect=')) {
      return '--inspect=0';
    }

    // If --inspect, or --inspect-brk - let it remain in execArgv.
    if (val.startsWith('--inspect-port=')) {
      return '--inspect-port=0';
    }
    return val;
  });
}

const assert = require('assert');
const forge = require('node-forge');
const { fork } = require('child_process');
const crypto = require('crypto');

const alg = 'aes192';
const cipherPwd = 'asbySdfhbne2347sbns&6329dsbnkhqp3nny39';

const cipher = crypto.createCipher(alg, cipherPwd);
const decipher = crypto.createDecipher(alg, cipherPwd);

/**
 * AES encryption.
 * @param {String} data - utf8 encoded string to encrypt.
 * @returns {String} - base64 encoded encrypted string.
 */
function encrypt(data) {
  let encrypted = cipher.update(data, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return encrypted;
}

/**
 * AES decryption.
 * @param {String} data  - base64 encoded encrypted string.
 * @returns {String} - utf8 encoded decrypted string.
 */
function decrypt(data) {
  let decrypted = decipher.update(data, 'base64', 'utf8');
  decrypted += cipher.final('utf8');
  return decrypted;
}

/**
 * Default certificate parameters. You can change them.
 */
exports.certCfg = {
  serialNumber: 1, // Is incremented during new certificates generation.
  defaultPassphrase: 'Dbsh4_e',
  minusDays: 2,
  plusDays: 366,
  keySize: 2048,
};

function checkCn(cn) {
  assert(cn && (typeof cn === 'string'), 'No Common Name for certificate');
}

/**
 * Generates RSA key pair.
 * @return {Object} - RSA keypair: { privateKey, publicKey }
 */
exports.genKeyPair = function genKeyPair() {
  const keyPair = crypto.generateKeyPairSync('rsa', {
    modulusLength: exports.certCfg.keySize,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  const forgeKeyPair = {};

  forgeKeyPair.privateKey = forge.pki.privateKeyFromPem(keyPair.privateKey);
  forgeKeyPair.publicKey = forge.pki.publicKeyFromPem(keyPair.publicKey);

  return forgeKeyPair;
};

/**
 * Generates 2048 bit, RSA key pair for SSH.
 * @param {String} comment - a comment for public key.
 * @param {String} [passPhrase] - a passphrase for private key.
 */
exports.genSSHKeyPair = function genSSHKeyPair(comment, passPhrase) {
  const keyPair = exports.genKeyPair();
  keyPair.publicKey = forge.ssh.publicKeyToOpenSSH(keyPair.publicKey, comment);
  keyPair.privateKey = forge.ssh.privateKeyToOpenSSH(keyPair.privateKey, passPhrase);
  return keyPair;
};

// Default attributes for certificate creation.
function getDefaultAttrs() {
  return [{
    name: 'countryName',
    value: 'CH',
  }, {
    name: 'localityName',
    value: 'Geneva',
  }, {
    name: 'organizationName',
    value: 'Unique Organization',
  }];
}

/**
 * Generates self-signed certificate by cn.
 * @param {String} cn - common name
 *
 * @param {String} [passPhrase] - pass phrase.
 * Some inner pass phrase is used as default,
 * so certificates with default pass phrase can be used only by this module API.
 *
 * @param {Array<Object>} [attrs] - three certificate attributes, like following:
 * ```
 * [{
    name: 'countryName',
    value: 'CH',
  }, {
    name: 'localityName',
    value: 'Geneva',
  }, {
    name: 'organizationName',
    value: 'Unuque Organization',
  }]
  ```
 * @returns {{cert: String, pfx: Buffer}}
 */
exports.genSSCert = function genSSCert(
  cn,
  passPhrase = exports.certCfg.defaultPassphrase,
  attrs = getDefaultAttrs()
) {
  checkCn(cn);
  attrs.push({
    name: 'commonName',
    value: cn,
  });

  const keyPair = exports.genKeyPair();

  const cert = forge.pki.createCertificate();

  cert.serialNumber = (exports.certCfg.serialNumber++).toString();
  cert.validity.notBefore = new Date();
  cert.validity.notBefore.setDate(cert.validity.notBefore.getDate() - exports.certCfg.minusDays);
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setDate(cert.validity.notAfter.getDate() + exports.certCfg.plusDays);
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.publicKey = keyPair.publicKey;
  cert.sign(keyPair.privateKey, forge.md.sha256.create());

  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
    keyPair.privateKey, cert, passPhrase/* , {algorithm: '3des'} */);

  const p12Der = forge.asn1.toDer(p12Asn1).getBytes();

  const buf = Buffer.from(forge.util.encode64(p12Der), 'base64');

  return {
    cert: forge.pki.certificateToPem(cert),
    pfx: buf,
  };
};

/**
 * Extracts CN from a certificate.
 *
 * @param {String} cert
 * @returns {String} CN of certificate.
 */
exports.getCertificateCn = function getCertificateCn(cert) {
  const forgeCert = forge.pki.certificateFromPem(cert);
  return forgeCert.subject.getField('CN').value;
};

/**
 * Extracts Serial number from a certificate.
 *
 * @param {String} cert
 * @returns {String} Serial number of certificate.
 */
exports.getCertificateSerNum = function getCertificateSerNum(cert) {
  const forgeCert = forge.pki.certificateFromPem(cert);
  return forgeCert.serialNumber;
};

// Array with certificate properties. Can be used for testing also.
exports.dataCertProps = [
  'subjectCn',
  'issuerCn',
  'serialNumber',
  'notAfter',
  'notBefore',
];

/**
 * Extracts data from certificate string or PFX buffer.
 *
 * @param {String | Buffer} certOrPfx - Certificate string or PFX Buffer.
 * @returns
 * {subjectCn: String, issuerCn: String, serialNumber: String, notBefore: Date, notAfter: Date}
 * }
 */
exports.extractCertData = function extractCertData(
  certOrPfx,
  passPhrase = exports.certCfg.defaultPassphrase
) {
  let forgeCert;
  if (Buffer.isBuffer(certOrPfx)) {
    const p12Der = forge.util.decode64(certOrPfx.toString('base64'));
    const p12Asn1 = forge.asn1.fromDer(p12Der);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, passPhrase);
    const bags = p12.getBags({ bagType: forge.pki.oids.certBag });
    forgeCert = bags[forge.pki.oids.certBag][0].cert;
  } else {
    forgeCert = forge.pki.certificateFromPem(certOrPfx);
  }
  const data = {
    subjectCn: forgeCert.subject.getField('CN').value,
    issuerCn: forgeCert.issuer.getField('CN').value,
    countryName: forgeCert.issuer.getField('C').value,
    organizationName: forgeCert.issuer.getField('O').value,
    serialNumber: forgeCert.serialNumber,
    notBefore: forgeCert.validity.notBefore,
    notAfter: forgeCert.validity.notAfter,
  };
  return data;
};

/**
 * Checks fields passed in options object, plus 'notBefore', 'notAfter' fields.
 * @param cert
 * @param {Object} [options]
 * @param {String} [options.subjectCn]
 * @param {String} [options.issuerCn]
 * @param {String} [options.serialNumber]
 * @param {Boolean} [options.throwIfWrong]
 *
 * @returns {Object} with boolean check results for each requested field
 * and for 'notBefore', 'notAfter' fields.
 * @throws {Error} if options.throwIfWrong is used and some checking is wrong.
 */
exports.checkCertificate = function checkCertificate(cert, options = {}) {
  const certData = exports.extractCertData(cert);
  const curDate = new Date();
  let totalRes = true;
  const res = {};
  let propName;

  function handleErr() {
    if (!res[propName]) {
      if (options.throwIfWrong) {
        throw new Error(`Error at checking: ${propName}`);
      }
      totalRes = false;
    }
  }

  for (let i = 0; i < 3; i++) {
    propName = exports.dataCertProps[i];
    if (options[propName]) {
      res[propName] = certData[propName] === options[propName];
      handleErr();
    }
  }

  propName = 'notBefore';
  res[propName] = curDate >= certData[propName];
  handleErr();

  propName = 'notAfter';
  res[propName] = curDate <= certData[propName];
  handleErr();

  res.totalRes = totalRes;
  return res;
};


function asyncHelper(params) {
  if (params.passPhrase) {
    params.passPhrase = encrypt(params.passPhrase); // eslint-disable-line no-param-reassign
  }
  return new Promise((resolve, reject) => {
    const child = fork(__filename, [], { execArgv: getChildExecArgv() });
    child.send(params);
    child.on('message', (msg) => {
      resolve(msg);
    });
    child.on('error', (err) => {
      reject(err);
    });
  });
}

/**
 * Generates self signed certificate asynchronously, in separate process.
 * @param {String} cn - common name
 *
 * @param {String} [passPhrase] - pass phrase.
 * Some inner pass phrase is used as default,
 * so certificates with default pass phrase can be used only by this module API.
 *
 * @param {Array<Object>} [attrs] - three certificate attributes, like following:
 * ```
 * [{
    name: 'countryName',
    value: 'CH',
  }, {
    name: 'localityName',
    value: 'Geneva',
  }, {
    name: 'organizationName',
    value: 'Unuque Organization',
  }]
 * @returns {Promise} Promise which is resolved to object
 * {cert (String), pfx (String in base64)}.
 */
exports.genSSCertAsync = function genSSCertAsync(cn, passPhrase, attrs) {
  checkCn(cn);

  const params = {
    cn,
    func: 'genSSCert',
  };

  if (attrs) {
    params.attrs = attrs;
  }

  return asyncHelper(params);
};

/**
 * Generates 2048 bit, RSA key pair in a separate process.
 */
exports.genKeyPairAsync = function genKeyPairAsync() {
  const params = {
    func: 'genKeyPair',
  };

  return asyncHelper(params);
};

/**
 * Generates 2048 bit, RSA key pair for SSH in a separate process.
 * @param {String} comment - a comment for public key.
 * @param {String} [passPhrase] - a passphrase for private key.
 */
exports.genSSHKeyPairAsync = function genSSHKeyPairAsync(comment, passPhrase) {
  const params = {
    func: 'genSSHKeyPair',
    comment,
    passPhrase,
  };

  return asyncHelper(params);
};

if (process.send) { // Child process.
  process.on('message', (msg) => {
    if (typeof msg === 'string') {
      return;
    }
    const {
      func, cn, attrs, comment,
    } = msg;
    let { passPhrase } = msg;
    if (passPhrase) {
      passPhrase = decrypt(passPhrase);
    }

    let res;

    switch (func) {
      case 'genKeyPair':
        res = exports[func]();
        break;
      case 'genSSHKeyPair':
        res = exports[func](comment, passPhrase);
        break;
      case 'genSSCert':
        res = exports[func](cn, passPhrase, attrs);
        res.pfx = res.pfx.toString('base64');
        break;
      default:
        throw new Error('Unknown function in async call.');
    }

    process.send(res, () => {
      // https://github.com/nodejs/node-v0.x-archive/issues/2605
      process.exit();
    });
  });
}
