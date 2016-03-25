'use strict';

var assert = require('assert');
var forge = require('node-forge');
var fork = require('child_process').fork;
var Promise = require('bluebird');

// Фикс для 2х-процессной отладки в WebStorm.
// http://stackoverflow.com/questions/16840623/how-to-debug-node-js-child-forked-process
var isDebug = typeof v8debug === 'object';
if (isDebug) {
    //Set an unused port number.
    process.execArgv.push('--debug=' + (40896));
}

var ursa;
try {
    ursa = require('ursa');
} catch (e) {
}

exports.certCfg = {
    serialNumber: 1,// Is incremented during new certificates generation.
    defaultPassphrase: 'Dbsh4_e', // TODO: add passphrase as an optional parameter for related functions.
    minusDays: 2,
    plusDays: 366,
    keySize: 2048
};

function checkCn(cn) {
    assert(cn && (typeof cn === 'string'), 'No Common Name for certificate');
}

/**
 * Generates certificate by cn.
 * @param cn
 * @returns {{cert: String, pfx: Buffer}}
 */
exports.genSSCert = function (cn) {

    checkCn(cn);

    // Constants:
    var attrs = [{
        name: 'commonName',
        value: cn
    }, {
        name: 'countryName',
        value: 'RU'
    }, {
        name: 'localityName',
        value: 'Moscow'
    }, {
        name: 'organizationName',
        value: 'R-Vision'
    }];

    var keyPair = {};
    if (ursa) {
        var privKey = ursa.generatePrivateKey(exports.certCfg.keySize);
        keyPair.privateKey = forge.pki.privateKeyFromPem(privKey.toPrivatePem());
        keyPair.publicKey = forge.pki.publicKeyFromPem(privKey.toPublicPem());
    } else {
        keyPair = forge.pki.rsa.generateKeyPair(exports.certCfg.keySize);
    }

    var cert = forge.pki.createCertificate();

    cert.serialNumber = (exports.certCfg.serialNumber++).toString();
    cert.validity.notBefore = new Date();
    cert.validity.notBefore.setDate(cert.validity.notBefore.getDate() - exports.certCfg.minusDays);
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setDate(cert.validity.notAfter.getDate() + exports.certCfg.plusDays);
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.publicKey = keyPair.publicKey;
    cert.sign(keyPair.privateKey, forge.md.sha256.create());

    var p12Asn1 = forge.pkcs12.toPkcs12Asn1(
        keyPair.privateKey, cert, exports.certCfg.defaultPassphrase/*, {algorithm: '3des'}*/);

    var p12Der = forge.asn1.toDer(p12Asn1).getBytes();

    var buf = new Buffer(forge.util.encode64(p12Der), 'base64');

    return {
        cert: forge.pki.certificateToPem(cert),
        pfx: buf
    };
};

/**
 * Extracts CN from a certificate.
 *
 * @param {String} cert
 * @returns {String} CN of certificate.
 */
exports.getCertificateCn = function (cert) {
    var forgeCert = forge.pki.certificateFromPem(cert);
    return forgeCert.subject.getField('CN').value;
};

/**
 * Extracts Serial number from a certificate.
 *
 * @param {String} cert
 * @returns {String} Serial number of certificate.
 */
exports.getCertificateSerNum = function (cert) {
    var forgeCert = forge.pki.certificateFromPem(cert);
    return forgeCert.serialNumber;
};

// Этот массив, в основном, для удобства тестирования.
exports.dataCertProps = [
    'subjectCn',
    'issuerCn',
    'serialNumber',
    'notAfter',
    'notBefore'
];

/**
 * Extracts data from certificate string or PFX buffer.
 *
 * @param {String | Buffer} certOrPfx - Certificate string or PFX Buffer.
 * @returns {
 * {subjectCn: String, issuerCn: String, serialNumber: String, notBefore: Date, notAfter: Date}
 * }
 */
exports.extractCertData = function (certOrPfx) {
    var forgeCert;
    if (Buffer.isBuffer(certOrPfx)) {
        var p12Der = forge.util.decode64(certOrPfx.toString('base64'));
        var p12Asn1 = forge.asn1.fromDer(p12Der);
        var p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, exports.certCfg.defaultPassphrase);
        var bags = p12.getBags({bagType: forge.pki.oids.certBag});
        forgeCert = bags[forge.pki.oids.certBag][0].cert;
    } else {
        forgeCert = forge.pki.certificateFromPem(certOrPfx);
    }
    var data = {
        subjectCn: forgeCert.subject.getField('CN').value,
        issuerCn: forgeCert.issuer.getField('CN').value,
        serialNumber: forgeCert.serialNumber,
        notBefore: forgeCert.validity.notBefore,
        notAfter: forgeCert.validity.notAfter
    };
    return data;
};

/**
 *
 * @param cert
 * @param {Object} [options]
 * @param {String} [options.subjectCn]
 * @param {String} [options.issuerCn]
 * @param {String} [options.serialNumber]
 *
 * @param {Boolean} [options.throwIfWrong]
 *
 * @returns {Object} with boolean check results for each requested field
 * and for notBefore, notAfter fields.
 * @throws {Error} if options.throwIfWrong is used and some checking is wrong.
 */
exports.checkCertificate = function (cert, options) {
    var certData = exports.extractCertData(cert);
    var curDate = new Date();
    var totalRes = true;
    var res = {};
    var propName;

    function handleErr() {
        if (!res[propName]) {
            if (options.throwIfWrong) {
                throw new Error('Error at checking: ' + propName);
            }
            totalRes = false;
        }
    }

    options = options || {};

    for (var i = 0; i < 3; i++) {
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

/**
 *
 * @param {String} cn
 * @returns {Promise} Promise which is resolved to object {cert (String), pfx (String in base64)}.
 */
exports.genSSCertAsync = function (cn) {
    return new Promise(function (resolve, reject) {
        checkCn(cn);
        var child = fork(__filename, [cn]);
        child.on('message', function (msg) {
            resolve(msg);
        });
        child.on('error', function (err) {
            reject(err);
        });
    });
};

if (process.send) { // Модуль вызван через fork.
    var cn = process.argv[2];
    if (cn) {
        var res = exports.genSSCert(cn);
        res.pfx = res.pfx.toString('base64');
        process.send(res);
    }
};
