const crypto = require('crypto');
const fs = require('fs');
const path = require('path');


function generateKeys() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });

    fs.writeFileSync('public_key.pem', publicKey);
    fs.writeFileSync('private_key.pem', privateKey);
    console.log('Keys generated and saved to files.');
}


function encryptFile(filePath) {
    const publicKey = fs.readFileSync('public_key.pem', 'utf8');
    const fileData = fs.readFileSync(filePath);

    const encryptedData = crypto.publicEncrypt(publicKey, Buffer.from(fileData));
    fs.writeFileSync(`${filePath}.enc`, encryptedData);
    console.log('File encrypted and saved.');
}


function decryptFile(encryptedFilePath) {
    const privateKey = fs.readFileSync('private_key.pem', 'utf8');
    const encryptedData = fs.readFileSync(encryptedFilePath);

    const decryptedData = crypto.privateDecrypt(privateKey, encryptedData);
    const originalFilePath = encryptedFilePath.replace('.enc', '');
    fs.writeFileSync(originalFilePath, decryptedData);
    console.log('File decrypted and saved.');
}


function signFile(filePath) {
    const privateKey = fs.readFileSync('private_key.pem', 'utf8');
    const fileData = fs.readFileSync(filePath);

    const sign = crypto.createSign('SHA256');
    sign.update(fileData);
    sign.end();

    const signature = sign.sign(privateKey, 'hex');
    fs.writeFileSync(`${filePath}.sig`, signature);
    console.log('File signed and signature saved.');
}


function verifyFile(filePath, signaturePath) {
    const publicKey = fs.readFileSync('public_key.pem', 'utf8');
    const fileData = fs.readFileSync(filePath);
    const signature = fs.readFileSync(signaturePath, 'utf8');

    const verify = crypto.createVerify('SHA256');
    verify.update(fileData);
    verify.end();

    const isValid = verify.verify(publicKey, signature, 'hex');
    console.log(`File integrity ${isValid ? 'verified' : 'could not be verified'}.`);
    return isValid;
}


const action = process.argv[2];
const filePath = process.argv[3];

if (action === 'generateKeys') {
    generateKeys();
} else if (action === 'encryptFile' && filePath) {
    encryptFile(filePath);
} else if (action === 'decryptFile' && filePath) {
    decryptFile(filePath);
} else if (action === 'signFile' && filePath) {
    signFile(filePath);
} else if (action === 'verifyFile' && filePath) {
    const signaturePath = `${filePath}.sig`;
    verifyFile(filePath, signaturePath);
} else {
    console.log('Invalid action or missing file path. Use "generateKeys", "encryptFile <filePath>", "decryptFile <filePath>", "signFile <filePath>", or "verifyFile <filePath>".');
}
