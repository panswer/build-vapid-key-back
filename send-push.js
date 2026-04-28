const crypto = require('node:crypto');

const subscription = {
    endpoint: "https://fcm.googleapis.com/fcm/send/ddjrUILf3xo:APA91bFoRB5E7n-4EI9EIrvOwBU5VKn__DWgbZhB226k2iKq2-K4fgr5uaRkxL-S0pwO3ZLgnlvN7vIUac8wMUb2b0x-bD86Ww4BbyVKxk2JAQjLXBES6GafTUH-mQK9tfOm_wHjv2si",
    expirationTime: null,
    keys: {
        p256dh: "BHlfIg5CEgOQG8vbgKgEbwnZ548CAj0usDzmLkKCWUpge4HuufDu5ZZHrL420xHCYVl6H_NdtgzPtVbs4jKfXr0",
        auth: "7Q46CUkymTAqqYgqyXpK0w"
    }
};

// Pega aquí los valores que se imprimieron en tu consola al correr push-script.js
const VAPID_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL2ZjbS5nb29nbGVhcGlzLmNvbSIsImV4cCI6MTc3Njk1ODQ2NCwic3ViIjoibWFpbHRvOnBhbnN3ZXJAZ21haWwuY29tIn0.A71MzPKzCrD9bFJ7xOJ0RhiuL4bCzRPJlkyC2L-PsuVsWYW6ZHCx4qac0z630Ju6_065vceG3ySxHvvj8HSujg";
const PUBLIC_KEY = "BNk4ewe3vwbcQJUK7Kusf99abfWjb5J6wY8l-7PoZN2lHZb1gZUkfnK8DhlrlnfcbcVCCwIfMu99p2fIatwxYak";

// Función auxiliar para decodificar las llaves Base64URL del navegador
function decodeBase64Url(base64url) {
    return Buffer.from(base64url.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

// Función que realiza la encriptación ECDH + AES-GCM (Nativo en Node.js, RFC 8291)
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

async function sendPushNotification() {
    console.log("Encriptando información y enviando petición push nativa a FCM...");
    
    // La información personalizada que enviaremos
    const customPayload = {
        title: "¡Notificación Nativa!",
        body: "Esta información fue encriptada usando crypto nativo en Node.js",
        url: "/"
    };

    const encryptedBody = encryptPayload(customPayload, subscription.keys);

    try {
        const response = await fetch(subscription.endpoint, {
            method: 'POST',
            headers: {
                'Authorization': `vapid t=${VAPID_TOKEN}, k=${PUBLIC_KEY}`,
                'TTL': '60',
                'Content-Encoding': 'aes128gcm', // Indicamos que el body viene encriptado en el estándar nuevo
                'Content-Type': 'application/octet-stream',
                'Content-Length': encryptedBody.length.toString()
            },
            body: encryptedBody
        });

        console.log("Status Code de FCM:", response.status);
        const responseText = await response.text();
        console.log("Respuesta de FCM:", responseText || "OK");
    } catch (error) {
        console.error("Error enviando:", error);
    }
}

sendPushNotification();
