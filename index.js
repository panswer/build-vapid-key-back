const crypto = require('node:crypto');
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');

dotenv.config();

const pbl = process.env.PUBLIC_KEY;
const prc = process.env.PRIVATE_KEY;

const app = express();

app.use(cors());
app.use(express.json());

const port = process.env.SERVER_PORT || 3000;

function decodeBase64Url(base64url) {
    return Buffer.from(base64url.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function encryptPayload(payload, keys) {
    // 1. Decodificar las llaves públicas y el secreto del cliente (navegador)
    const clientPublicKey = decodeBase64Url(keys.p256dh);
    const clientAuth = decodeBase64Url(keys.auth);

    // 2. Generar un par de llaves efímeras P-256 en el servidor
    const ecdh = crypto.createECDH('prime256v1');
    const serverPublicKey = ecdh.generateKeys(); // Retorna los 65 bytes en formato uncompressed (empieza con 0x04)
    const sharedSecret = ecdh.computeSecret(clientPublicKey);

    // 3. Derivación de Llaves (HKDF-SHA256)
    const salt = crypto.randomBytes(16);

    // Derivar Material de Llave Inicial (IKM)
    const infoAuth = Buffer.concat([Buffer.from('WebPush: info\0', 'utf8'), clientPublicKey, serverPublicKey]);
    const ikm = crypto.hkdfSync('sha256', sharedSecret, clientAuth, infoAuth, 32);

    // Derivar la Llave de Encriptación de Contenido (CEK) y el Nonce
    const cek = crypto.hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: aes128gcm\0', 'utf8'), 16);
    const nonce = crypto.hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: nonce\0', 'utf8'), 12);

    // 4. Preparar el contenido (Payload) añadiendo padding (0x02 indica fin de registro)
    const paddedPayload = Buffer.concat([Buffer.from(JSON.stringify(payload), 'utf8'), Buffer.from([0x02])]);

    // 5. Encriptar el payload utilizando aes-128-gcm
    const cipher = crypto.createCipheriv('aes-128-gcm', cek, nonce);
    const ciphertext = Buffer.concat([cipher.update(paddedPayload), cipher.final(), cipher.getAuthTag()]);

    // 6. Construir el paquete binario de la petición (Header + Ciphertext)
    const rsBuffer = Buffer.alloc(4);
    rsBuffer.writeUInt32BE(4096, 0); // Tamaño del registro (generalmente 4096 bytes)
    const idlenBuffer = Buffer.from([serverPublicKey.length]);

    return Buffer.concat([salt, rsBuffer, idlenBuffer, serverPublicKey, ciphertext]);
}

app.post('/push-notification', async (req, res) => {
    const { endpoint, keys } = req.body;

    const prcObj = JSON.parse(Buffer.from(prc, 'base64'));
    const privateKey = crypto.createPrivateKey({
        key: prcObj,
        format: 'jwk',
    });

    const origin = new URL(endpoint).origin;

    const claims = {
        aud: origin,
        exp: Math.floor(Date.now() / 1000) + (12 * 60 * 60),
        sub: "mailto:panswer@gmail.com",
    };

    const header = {
        typ: 'JWT',
        alg: 'ES256'
    };

    const headerBase64Url = Buffer.from(JSON.stringify(header)).toString('base64url');
    const claimsBase64Url = Buffer.from(JSON.stringify(claims)).toString('base64url');

    const dataToSign = [headerBase64Url, claimsBase64Url].join('.');

    const signature = crypto.sign(
        'sha256',
        Buffer.from(dataToSign),
        {
            key: privateKey,
            dsaEncoding: 'ieee-p1363'
        }
    );
    const signatureBase64Url = Buffer.from(signature).toString('base64url');

    const vapidToken = [dataToSign, signatureBase64Url].join('.');

    const encryptedBody = encryptPayload(
        {
            title: "¡Notificación Nativa!",
            body: "<strong>Esta información fue encriptada usando crypto nativo en Node.js</strong>",
            url: '/'
        },
        keys
    );

    try {
        const response = await fetch(
            endpoint,
            {
                method: 'POST',
                headers: {
                    'Authorization': `vapid t=${vapidToken}, k=${pbl}`,
                    'TTL': '60',
                    'Content-Encoding': 'aes128gcm',
                    'Content-Type': 'application/octet-stream',
                    'Content-Length': encryptedBody.length.toString()
                },
                body: encryptedBody
            }
        )
            .then(res => {
                console.log(res.status);
                return res.text();
            });

        console.log(response);
    } catch (error) {
        console.log(error);
    }

    res.status(201).json({
    })
});

app.listen(
    port, err => {
        if (err) {
            console.log(err);
            process.exit(1);
        }

        console.log(`Server on port ${port}`);
    }
)