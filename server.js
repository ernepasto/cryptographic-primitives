const { createDiffieHellman } = require('crypto');
const { hmac, cipher, util, random } = require('node-forge');

const express = require('express');
const { createServer } = require('http');
const { Server } = require('socket.io');

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer);

app.get('/', (req, res) => {
    res.send('<p>The server is running...</p>');
});  

httpServer.listen(3000, () => {
    console.log('listening on port 3000');
});




let plaintext = 'The European languages are members of the same family. Their separate existence is a myth.';
let chipertext = '';
let AESkey = null; //AES encryption key
let chiperAES = null;




/* Scambio dei parametri p, g e x alla connessione con un nuovo client */
io.on('connection', (socket) => {
    
    console.log('The client ' + socket.id + ' is connected');

    /* Generazione dei parametri di Diffie Hellman */
    let diffieHellman = null;  
    let p, g, x, y;
    diffieHellman = createDiffieHellman(192); // 192 = 32 byte key for AES-256 
    p = diffieHellman.getPrime();
    g = diffieHellman.getGenerator();
    x = diffieHellman.generateKeys('base64');
    socket.emit('paramsExchange', { prime: p, generator: g, exponential: x });
    
    /* Acquisizione dell'esponente scelto dal client e generazione della chiave per AES */
    socket.on('expExchange', (params) => {
        y = params.exponential;
        AESkey = diffieHellman.computeSecret(y, 'base64', 'base64');

        /* Invio del messaggio cifrato con AES */
        let iv = random.getBytesSync(16);
        chiperAES = cipher.createCipher('AES-CBC', AESkey);
        chiperAES.start({iv: iv});
        chiperAES.update(util.createBuffer(plaintext));
        chiperAES.finish();
        chipertext = chiperAES.output;
        socket.emit('encryptedMsg', { chipertext: chipertext, iv: iv });
    });

});

/* Creazione MAC con HMAC
const mac = hmac.create();
mac.start('sha512', MACkey);
mac.update(chipertext);
const digest = mac.digest().toHex();
*/