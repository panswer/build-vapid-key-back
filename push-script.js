const crypto = require('node:crypto');

function toBase64Url(buffer) {
  return buffer.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
});

// Extraemos la llave pública cruda (formato uncompressed de 65 bytes)
// Usando JWK es la manera más segura de obtener las coordenadas exactas de la curva
const jwk = publicKey.export({ format: 'jwk' });
const x = Buffer.from(jwk.x, 'base64url');
const y = Buffer.from(jwk.y, 'base64url');
const rawPublicKey = Buffer.concat([Buffer.from([0x04]), x, y]);

const publicKeyBase64Url = toBase64Url(rawPublicKey);

const claims = {
    // https://updates.push.services.mozilla.com Mozilla
    aud: "https://fcm.googleapis.com",
    exp: Math.floor(Date.now() / 1000) + (12 * 60 * 60),
    sub: "mailto:panswer@gmail.com",
};

const header = {
    typ: 'JWT',
    alg: 'ES256'
};


const headerBase64Url = toBase64Url(Buffer.from(JSON.stringify(header)));
const claimsBase64Url = toBase64Url(Buffer.from(JSON.stringify(claims)));

const dataToSign = [headerBase64Url, claimsBase64Url].join('.');

const signature = crypto.sign(
    'sha256',
    Buffer.from(dataToSign),
    {
        key: privateKey,
        dsaEncoding: 'ieee-p1363'
    }
);

const signatureBase64Url = toBase64Url(signature);

const vapidToken = [dataToSign, signatureBase64Url].join('.');

console.log(`PUBLIC_KEY (Para el frontend): ${publicKeyBase64Url}`);
console.log(`\nHeader para enviar la notificación:\nAuthorization: vapid t=${vapidToken}, k=${publicKeyBase64Url}`);
