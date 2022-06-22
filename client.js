const { createDiffieHellman } = require('crypto');
const { hmac, cipher, util, random } = require('node-forge');

const { io } = require('socket.io-client');
const socket = io('http://localhost:3000/');

socket.on('connect', () => {
    console.log('Connection id: ' + socket.id); 
});

socket.on('disconnect', () => {
    console.log('client disconnected');
});





let chipertext = '';
let plaintext = '';
let AESkey = null; //AES encryption key
let decipherAES = null;




/* Acquisizione dei parametri p, g e x inviati dal server, generazione della chiave per AES */
socket.on('paramsExchange', (params) => {

    /* Generazione dei parametri di Diffie Hellman e generazione della chiave per AES*/
    let diffieHellman = null;
    let p, g, y, x;
    p = params.prime;
    g = params.generator;
    x = params.exponential;
    diffieHellman = createDiffieHellman(p, g);
    y = diffieHellman.generateKeys('base64');

    AESkey = diffieHellman.computeSecret(x, 'base64', 'base64');

    /* Invio dell'esponente y scelto */
    socket.emit('expExchange', { exponential: y });
});

/* Utilizzo di AES per decifrare il chipertext ricevuto */
socket.on('encryptedMsg', (params) => {
    chipertext = params.chipertext;
    let iv = params.iv;
    decipherAES = cipher.createDecipher('AES-CBC', AESkey);
    decipherAES.start({ iv: iv });
    decipherAES.update(util.createBuffer(chipertext));
    plaintext = decipherAES.output.toString();
    console.log(plaintext);
});