/**
 * IdentityShield v3 - Cryptographic HMAC-SHA256 Signing Module
 * Web Crypto API implementation strictly adhering to context.md Section 17 and PRD §25.
 *
 * Rules:
 * 1. String to sign: `${timestamp}\n${nonce}\n${body_sha256_hex}`
 * 2. Secret is kept strictly in-memory (never written to storage or printed to console).
 * 3. Headers: X-IS-Key-Id, X-IS-Timestamp, X-IS-Nonce, X-IS-Signature, Content-Type, ngrok-skip-browser-warning.
 */

(function (window) {
  'use strict';

  /**
   * Converts an ArrayBuffer to a lowercase hexadecimal string.
   * @param {ArrayBuffer} buffer
   * @returns {string}
   */
  function bufToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
  }

  /**
   * Generates a cryptographically secure random hexadecimal nonce (16 bytes = 32 hex chars).
   * @returns {string}
   */
  function generateNonce() {
    if (window.crypto && typeof window.crypto.getRandomValues === 'function') {
      try {
        const bytes = new Uint8Array(16);
        window.crypto.getRandomValues(bytes);
        return bufToHex(bytes.buffer);
      } catch (e) {
        console.warn('getRandomValues failed, using fallback nonce generator', e);
      }
    }
    let hex = '';
    for (let i = 0; i < 32; i++) {
      hex += Math.floor(Math.random() * 16).toString(16);
    }
    return hex;
  }

  /**
   * Computes the SHA-256 hash of a UTF-8 string.
   * Uses Web Crypto API when available, otherwise falls back to pure JS window.sha256.
   * @param {string} text
   * @returns {Promise<string>} Hex representation of SHA-256
   */
  async function sha256Hex(text) {
    if (window.crypto && window.crypto.subtle) {
      try {
        const enc = new TextEncoder();
        const data = enc.encode(text);
        const hashBuf = await window.crypto.subtle.digest('SHA-256', data);
        return bufToHex(hashBuf);
      } catch (e) {
        console.warn('WebCrypto digest failed, falling back to window.sha256', e);
      }
    }
    if (typeof window.sha256 === 'function') {
      return window.sha256(text);
    }
    throw new Error('No SHA-256 implementation available');
  }

  /**
   * Computes HMAC-SHA256 of message string using secret key.
   * Uses Web Crypto API when available, otherwise falls back to pure JS window.sha256.hmac.
   * @param {string} secret
   * @param {string} message
   * @returns {Promise<string>} Hex representation of HMAC-SHA256
   */
  async function hmacSha256Hex(secret, message) {
    if (window.crypto && window.crypto.subtle) {
      try {
        const enc = new TextEncoder();
        const keyData = enc.encode(secret);
        const msgData = enc.encode(message);

        const cryptoKey = await window.crypto.subtle.importKey(
          'raw',
          keyData,
          { name: 'HMAC', hash: 'SHA-256' },
          false,
          ['sign']
        );

        const sigBuf = await window.crypto.subtle.sign('HMAC', cryptoKey, msgData);
        return bufToHex(sigBuf);
      } catch (e) {
        console.warn('WebCrypto sign failed, falling back to window.sha256.hmac', e);
      }
    }
    if (typeof window.sha256 === 'function' && typeof window.sha256.hmac === 'function') {
      return window.sha256.hmac(secret, message);
    }
    throw new Error('No HMAC-SHA256 implementation available');
  }

  /**
   * Signs an ingest request body and returns required headers.
   *
   * @param {string} keyId - Registered Ingest Key ID
   * @param {string} secret - Ingest Secret Key (In-Memory Only)
   * @param {string} rawBody - Exact serialized JSON string of the request body
   * @param {object} [options] - Optional overrides for testing/tampering
   * @param {number} [options.timestamp] - Override Unix timestamp in seconds
   * @param {string} [options.nonce] - Override 16+ byte hex nonce
   * @param {string} [options.tamperSignature] - Provide deliberate bad signature
   * @param {boolean} [options.omitHeaders] - Omit X-IS-* headers for unsigned test
   * @returns {Promise<{headers: Record<string, string>, timestamp: number, nonce: string, bodyHash: string}>}
   */
  async function signRequest(keyId, secret, rawBody, options = {}) {
    if (options.omitHeaders) {
      return {
        headers: {
          'Content-Type': 'application/json',
          'ngrok-skip-browser-warning': 'true'
        },
        timestamp: 0,
        nonce: '',
        bodyHash: ''
      };
    }

    const timestamp = options.timestamp !== undefined ? options.timestamp : Math.floor(Date.now() / 1000);
    const nonce = options.nonce || generateNonce();
    const bodyHash = await sha256Hex(rawBody);

    const stringToSign = `${timestamp}\n${nonce}\n${bodyHash}`;
    let signature = '';

    if (options.tamperSignature) {
      signature = options.tamperSignature;
    } else {
      signature = await hmacSha256Hex(secret, stringToSign);
    }

    const headers = {
      'X-IS-Key-Id': keyId,
      'X-IS-Timestamp': String(timestamp),
      'X-IS-Nonce': nonce,
      'X-IS-Signature': signature,
      'Content-Type': 'application/json',
      'ngrok-skip-browser-warning': 'true'
    };

    return {
      headers,
      timestamp,
      nonce,
      bodyHash
    };
  }

  // Export to global window object
  window.ShieldSign = {
    signRequest,
    generateNonce,
    sha256Hex,
    hmacSha256Hex
  };
})(window);
