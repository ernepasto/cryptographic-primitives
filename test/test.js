const { createDiffieHellman } = require('crypto');
const { hmac, cipher, util, random } = require('node-forge');

const message = 'The European languages are members of the same family. Their separate existence is a myth.';

/* Diffie-hellman per lo scambio della chiave privata e della chiave per HMAC */
const diffieHellman = createDiffieHellman(192); //192 = 32 byte key for AES-256 
const prime = diffieHellman.getPrime();
const generator = diffieHellman.getGenerator();
const choosenValue = diffieHellman.generateKeys('base64');

// =============
const bob = createDiffieHellman(prime, generator);
const bobKey = bob.generateKeys('base64');
const bobSecret = bob.computeSecret(choosenValue, 'base64', 'base64');
// =============

const AESkey = diffieHellman.computeSecret(bobKey, 'base64', 'base64');
const MACkey = diffieHellman.computeSecret(bobKey, 'base64', 'base64');

console.log(AESkey);
console.log(MACkey);

/* AES-CBC per cifrare il messaggio da inviare */
const iv = random.getBytesSync(16);
const AES = cipher.createCipher('AES-CBC', AESkey);
AES.start({iv: iv});
AES.update(util.createBuffer(message));
AES.finish();
const result = AES.output;
const encryptedMessage = result.toHex();

/* HMAC per avere autenticazione e integrità del messaggio (encrypt-then-MAC) */
const mac = hmac.create();
mac.start('sha512', AESkey);
mac.update(encryptedMessage);
const digest = mac.digest().toHex();

//console.log('The encrypted message is: ' + encryptedMessage);
//console.log('The HMAC of the encrypted message is: ' + digest);