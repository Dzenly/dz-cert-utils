# 0.2.4

* Added genKeyPair(), genSSHKeyPair(), genKeyPairAsync(), genSSHKeyPairAsync().
* genSSCert() is now take passPhrase and attrs parameters.
* Dependencies are frozen by package-lock.json.

# 1.0.0

* Removed usage of ursa. But now minimal supported version of node.js is 10.12.0.
* Removed tia from dev deps. Use npm i -g tia for tests.
