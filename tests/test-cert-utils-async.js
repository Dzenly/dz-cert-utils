#! /usr/bin/env node

'use strict';

/* eslint-disable no-console */

const util = require('util');
const certUtils = require('../');
const timer = require('dz-timer-utils');
const dateUtils = require('dz-date-utils');
const t = require('tia/tmp-light-utils');

t.init(true, true);

const gCn = 'SomeCN';

function BoolAccummulator() {
  this.res = true;
  this.and = function and(res) {
    if (!res) {
      this.res = false;
    }
  };
}

function checkCert(actData, exp) {
  const acc = new BoolAccummulator();
  for (let i = 0, len = certUtils.dataCertProps.length; i < len; i++) {
    const propName = certUtils.dataCertProps[i];
    const propType = typeof actData[propName];
    const msg = `${propName} check`;
    if (propType === 'string') {
      acc.and(t.eq(actData[propName], exp[propName], msg));
    } else if (propType === 'object') {
      acc.and(t.eqDays(actData[propName], exp[propName], msg));
    }
  }
  return acc.res;
}

const origMinusDays = certUtils.certCfg.minusDays;
const origPlusDays = certUtils.certCfg.plusDays;
const certObj = certUtils.genSSCert(gCn);
const certData = certUtils.extractCertData(certObj.cert);
const curDate = new Date();

t.msg('Check for certificate parameters');

const certCheckRes = checkCert(certData, {
  subjectCn: gCn,
  issuerCn: gCn,
  serialNumber: '01',
  notBefore: dateUtils.addDaysToDate(curDate, -origMinusDays),
  notAfter: dateUtils.addDaysToDate(curDate, origPlusDays),
});
t.eq(certCheckRes, true, 'Whole certificate check');

// TODO: tests for minusDate + Date in couple with checks with created certificaes.

let checkRes = certUtils.checkCertificate(certObj.cert, {
  subjectCn: gCn,
  issuerCn: gCn,
  serialNumber: '01',
});
let checkRes1 = certUtils.checkCertificate(certObj.pfx, {
  subjectCn: gCn,
  issuerCn: gCn,
  serialNumber: '01',
});
console.log(util.inspect(checkRes));
t.eqObjects(checkRes, checkRes1, 'Objects comparison');

checkRes = certUtils.checkCertificate(certObj.cert);
checkRes1 = certUtils.checkCertificate(certObj.pfx);
console.log(util.inspect(checkRes));
t.eqObjects(checkRes, checkRes1, 'Objects comparison');

checkRes = certUtils.checkCertificate(certObj.cert, {
  subjectCn: 'Non correct Cn',
  issuerCn: gCn,
  serialNumber: '02',
});
checkRes1 = certUtils.checkCertificate(certObj.pfx, {
  subjectCn: 'Non correct Cn',
  issuerCn: gCn,
  serialNumber: '02',
});
console.log(util.inspect(checkRes));
t.eqObjects(checkRes, checkRes1, 'Objects comparison');

t.msg('Bad case, using throw');
try {
  checkRes = certUtils.checkCertificate(certObj.cert, {
    subjectCn: 'Non correct Cn',
    issuerCn: gCn,
    serialNumber: '02',
    throwIfWrong: true,
  });
  t.fail('Unexpected ansense of throw');
} catch (e) {
  t.pass(`Expected throw: ${e}`);
}

t.msg('Get certificate cn from not certificate string, should throw');
let cn;
try {
  cn = certUtils.getCertificateCn('asdfasdfasdfasd');
  t.fail(`Unexpected non throw, cn: ${cn}`);
} catch (e) {
  t.pass(`Expected throw: ${e.message}`);
}

t.msg('Generation of correct certificate');
const timerObj = timer.startTimer('Async Certificate Generation');
const p = certUtils.genSSCertAsync(gCn);

p.then((res) => {
  timerObj.stopTimer();

  cn = certUtils.getCertificateCn(res.cert);
  t.eq(cn, gCn, 'Checking CN');
  t.msg(`Serial Number: ${certUtils.getCertificateSerNum(res.cert)}`);
}).catch((err) => {
  t.fail(err);
}).then(() => {
  t.msg('Generation a certificate without CN, should fail');
  return certUtils.genSSCertAsync();
}).then((res) => {
  t.fail(`Here should be error:${certUtils.getCertificateCn(res.cert)}`);
}, (err) => {
  t.eq(err.name, 'AssertionError [ERR_ASSERTION]', 'Expected assertion');
  // t.checkAssertion(err, 'Expected assertion');
}).then(() => {
  const attrs = [{
    name: 'countryName',
    value: 'AA',
  }, {
    name: 'localityName',
    value: 'BBBB',
  }, {
    name: 'organizationName',
    value: 'CCCCC',
  }];
  return certUtils.genSSCertAsync('New cn', undefined, attrs);
}).then((res) => {
  console.log(certUtils.extractCertData(res.cert));
}).then(() => {
  return certUtils.genKeyPairAsync();
}).then((res) => {
  t.eq(Boolean(res), true, 'Key pair is generated.');
  return certUtils.genSSHKeyPairAsync('user@machine');
}).then((res) => {
  t.eq(Boolean(res), true, 'SSH Key pair is generated.');

  t.msg('Get SSH Public key from Private key w/o passphrase');

  return certUtils.privateKeyToPublicKeyAsync(res.privateKey, '', {
    openssh: true,
    comment: 'user@machine',
  })
    .then((pubkey) => {
      t.eq(res.publicKey, pubkey, 'Expected correct public key');

      return certUtils.genSSHKeyPairAsync('user@machine', 'passPhrase');
    })
    .then((keyPair) => {
      t.msg('Get SSH Public key from Private key w/ passphrase');

      return certUtils.privateKeyToPublicKeyAsync(keyPair.privateKey, 'passPhrase', {
        openssh: true,
        comment: 'user@machine',
      })
      .then((pubkey) => {
        t.eq(keyPair.publicKey, pubkey, 'Expected correct public key');
      });
    });
}).then(() => {
  t.total();
});
