'use strict';
var util = require('util');
var certUtils = require('cert-utils');
var timer = require('timer-utils');
var dateUtils = require('date-ex');
var t = require('tia/tmp-light-utils');
t.init(true, true);

var gCn = 'SomeCN';

function BoolAccummulator() {
    this.res = true;
    this.and = function(res) {
        if (!res) {
            this.res = false;
        }
    };
}

function checkCert(actData, exp) {

    var acc = new BoolAccummulator();
    for (var i = 0, len = certUtils.dataCertProps.length; i < len; i++) {
        var propName = certUtils.dataCertProps[i];
        var propType = typeof actData[propName];
        var msg = propName + ' check';
        if (propType === 'string') {
            acc.and(t.eq(actData[propName], exp[propName], msg));
        } else if (propType === 'object') {
            acc.and(t.eqDays(actData[propName], exp[propName], msg));
        }
    }
    return acc.res;
}

var origMinusDays = certUtils.certCfg.minusDays;
var origPlusDays = certUtils.certCfg.plusDays;
var certObj = certUtils.genSSCert(gCn);
var certData = certUtils.extractCertData(certObj.cert);
var curDate = new Date();

t.msg('Check for certificate parameters');

var res = checkCert(certData, {
    subjectCn: gCn,
    issuerCn: gCn,
    serialNumber: '01',
    notBefore: dateUtils.addDaysToDate(curDate, -origMinusDays),
    notAfter: dateUtils.addDaysToDate(curDate, origPlusDays)
});
t.eq(res, true, 'Whole certificate check');

// TODO: tests for minusDate + Date in couple with checks with created certificaes.

var checkRes = certUtils.checkCertificate(certObj.cert, {
    subjectCn: gCn,
    issuerCn: gCn,
    serialNumber: '01'
});
var checkRes1 = certUtils.checkCertificate(certObj.pfx, {
    subjectCn: gCn,
    issuerCn: gCn,
    serialNumber: '01'
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
    serialNumber: '02'
});
checkRes1 = certUtils.checkCertificate(certObj.pfx, {
    subjectCn: 'Non correct Cn',
    issuerCn: gCn,
    serialNumber: '02'
});
console.log(util.inspect(checkRes));
t.eqObjects(checkRes, checkRes1, 'Objects comparison');

t.msg('Bad case, using throw');
try {
    checkRes = certUtils.checkCertificate(certObj.cert, {
        subjectCn: 'Non correct Cn',
        issuerCn: gCn,
        serialNumber: '02',
        throwIfWrong: true
    });
    t.fail('Unexpected ansense of throw');
} catch (e) {
    t.pass('Expected throw: ' + e);
}

t.msg('Get certificate cn from not certificate string, should throw');
var cn;
try {
    cn = certUtils.getCertificateCn('asdfasdfasdfasd');
    t.fail('Unexpected non throw, cn: ' + cn);
} catch (e) {
    t.pass('Expected throw: ' + e.message);
}

t.msg('Generation of correct certificate');
var timerObj = timer.startTimer('Certificate Generation');
var p = certUtils.genSSCertAsync(gCn);

p.then(function (res) {
    timerObj.stopTimer();

    var cn = certUtils.getCertificateCn(res.cert);
    t.eq(cn, gCn, 'Checking CN');
    t.msg('Serial Number: ' + certUtils.getCertificateSerNum(res.cert));
}).catch(function (err) {
    t.fail(err);
}).then(function (res) {
    t.msg('Generation a certificate without CN, should fail')
    return certUtils.genSSCertAsync();
}).then(function (res) {
    t.fail('Here should be error:' + certUtils.getCertificateCn(res.cert));
}, function (err) {
    t.checkAssertion(err, 'Expected assertion');
}).then(function (res) {
    t.total();
});

