import CryptoJS from "crypto-js";

// Derive a shared secret using ECDH
export async function deriveSharedSecret(otherPublicKeyHex) {
    const privateKeyHex = localStorage.getItem("privateKey");
    if (!privateKeyHex) throw new Error("Private key not found in localStorage.");

    const privateKeyBuffer = hexToArrayBuffer(privateKeyHex);
    const otherPublicKeyBuffer = hexToArrayBuffer(otherPublicKeyHex);

    const privateKey = await window.crypto.subtle.importKey(
        "pkcs8",
        privateKeyBuffer,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveBits"]
    );

    const publicKey = await window.crypto.subtle.importKey(
        "spki",
        otherPublicKeyBuffer,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        []
    );

    const sharedSecretBuffer = await window.crypto.subtle.deriveBits(
        { name: "ECDH", public: publicKey },
        privateKey,
        256
    );

    const sharedSecret = CryptoJS.enc.Hex.stringify(CryptoJS.lib.WordArray.create(new Uint8Array(sharedSecretBuffer)));
    console.log("Shared secret:", sharedSecret);
    return sharedSecret;
}

export async function deriveKeys() {
    const algorithm = { name: "ECDH", namedCurve: "P-256" };

    const keyPair = await window.crypto.subtle.generateKey(
        algorithm,
        true,
        ["deriveKey", "deriveBits"]
    );

    const privateKey = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    const publicKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);

    const privateKeyHex = arrayBufferToHex(privateKey);
    const publicKeyHex = arrayBufferToHex(publicKey);

    localStorage.setItem("privateKey", privateKeyHex);
    localStorage.setItem("publicKey", publicKeyHex);
}



export async function encryptMessage (message, publicKey){
    const sharedSecretHex = await deriveSharedSecret(publicKey);
    const sharedSecret = CryptoJS.enc.Hex.parse(sharedSecretHex);
    
    const iv = CryptoJS.lib.WordArray.random(16); // Random IV

    const encrypted = CryptoJS.AES.encrypt(message, sharedSecret, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
    });

    
    return {
        ciphertext: encrypted.ciphertext.toString(CryptoJS.enc.Hex),
        iv: iv.toString(CryptoJS.enc.Hex),
    };
}

export function decryptMessage(ciphertextHex, ivHex, sharedSecretHex) {
    console.log("Decrypting message...");
   
    const sharedSecret = CryptoJS.enc.Hex.parse(sharedSecretHex);
    const iv = CryptoJS.enc.Hex.parse(ivHex);
    const ciphertext = CryptoJS.enc.Hex.parse(ciphertextHex);

    const decrypted = CryptoJS.AES.decrypt(
        { ciphertext: ciphertext },
        sharedSecret,
        {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7,
        }
    );

   
    const decryptedMessage = decrypted.toString(CryptoJS.enc.Utf8);
    console.log("Decrypted message string:", decryptedMessage);

    return decryptedMessage
}
function hexToArrayBuffer(hex) {
    // Check if the provided hex string has even length
    if (hex.length % 2 !== 0) {
        throw new Error("Hex string length must be even.");
    }

    const bytes = new Uint8Array(hex.length / 2);  // Create an array with half the length of the hex string

    for (let i = 0; i < bytes.length; i++) {
        // Convert each pair of hex characters into a byte and store it in the bytes array
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes.buffer;  // Return the ArrayBuffer of the byte array
}

function arrayBufferToHex(buffer) {
    const byteArray = new Uint8Array(buffer);
    return Array.from(byteArray)
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
   
}
