// ===== CRYPTO UTILITIES FOR WISE HUB LOCKER =====
// Client-side encryption library for BIP39, AES-GCM, RSA-OAEP

// ===== HELPER FUNCTIONS =====

function stringToArrayBuffer(str) {
    return new TextEncoder().encode(str);
}

function arrayBufferToString(buffer) {
    return new TextDecoder().decode(buffer);
}

function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const chunkSize = 0x8000;
    
    for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
    }
    
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// ===== PBKDF2 KEY DERIVATION =====

async function deriveKey(seedArray, salt, iterations = 100000) {
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        seedArray,
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    
    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: stringToArrayBuffer(salt),
            iterations: iterations,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// ===== AES-GCM ENCRYPTION =====

async function encryptAESGCM(text, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encodedText = stringToArrayBuffer(text);
    
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encodedText
    );
    
    const encryptedArray = new Uint8Array(iv.length + encrypted.byteLength);
    encryptedArray.set(iv);
    encryptedArray.set(new Uint8Array(encrypted), iv.length);
    
    return encryptedArray;
}

async function decryptAESGCM(encryptedArray, key) {
    const iv = encryptedArray.slice(0, 12);
    const data = encryptedArray.slice(12);
    
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        data
    );
    
    return arrayBufferToString(decrypted);
}

// ===== RSA-OAEP KEY GENERATION =====

async function generateRSAKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
    );
    
    const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    
    return {
        publicKey: arrayBufferToBase64(publicKey),
        privateKey: arrayBufferToBase64(privateKey)
    };
}

// ===== RSA-OAEP ENCRYPTION =====

async function encryptRSA(publicKeyBase64, data) {
    const publicKey = await crypto.subtle.importKey(
        "spki",
        base64ToArrayBuffer(publicKeyBase64),
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
    );
    
    const encodedData = stringToArrayBuffer(data);
    const encryptedData = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        encodedData
    );
    
    return arrayBufferToBase64(encryptedData);
}

async function decryptRSA(privateKeyBase64, encryptedDataBase64) {
    const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        base64ToArrayBuffer(privateKeyBase64),
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["decrypt"]
    );
    
    const encryptedData = base64ToArrayBuffer(encryptedDataBase64);
    const decryptedData = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        encryptedData
    );
    
    return arrayBufferToString(decryptedData);
}

// ===== BIP39 FUNCTIONS =====

let cachedWordlist = null;

async function loadWordlist() {
    if (cachedWordlist) return cachedWordlist;
    
    try {
        const response = await fetch('./js/bip39-wordlist.json');
        cachedWordlist = await response.json();
        return cachedWordlist;
    } catch (error) {
        console.error('Failed to load BIP39 wordlist:', error);
        throw new Error('Failed to load wordlist. Please refresh the page.');
    }
}

async function bip39WordsToUint8Array(mnemonicArray, wordList) {
    if (!Array.isArray(wordList)) {
        throw new Error("Word list must be an array");
    }
    
    const indexArray = mnemonicArray.map(word => {
        const index = wordList.indexOf(word.toLowerCase().trim());
        if (index === -1) {
            throw new Error(`Invalid BIP39 word: ${word}`);
        }
        return index;
    });
    
    const byteArray = [];
    let bitStream = indexArray.map(num => num.toString(2).padStart(11, '0')).join('');
    
    for (let i = 0; i < bitStream.length; i += 8) {
        let byteChunk = bitStream.slice(i, i + 8);
        byteArray.push(parseInt(byteChunk.padEnd(8, '0'), 2));
    }
    
    return new Uint8Array(byteArray);
}

async function generateBIP39Words(count = 12) {
    const wordlist = await loadWordlist();
    const words = [];
    
    for (let i = 0; i < count; i++) {
        const randomIndex = crypto.getRandomValues(new Uint32Array(1))[0] % wordlist.length;
        words.push(wordlist[randomIndex]);
    }
    
    return words;
}

// ===== EXPORT ALL FUNCTIONS =====

window.CryptoUtils = {
    stringToArrayBuffer,
    arrayBufferToString,
    arrayBufferToBase64,
    base64ToArrayBuffer,
    deriveKey,
    encryptAESGCM,
    decryptAESGCM,
    generateRSAKeyPair,
    encryptRSA,
    decryptRSA,
    bip39WordsToUint8Array,
    loadWordlist,
    generateBIP39Words
};

console.log('✅ CryptoUtils loaded successfully');