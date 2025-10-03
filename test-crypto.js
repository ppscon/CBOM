// Test file with various crypto algorithms
const crypto = require('crypto');

// MD5 - should be detected as HIGH risk
const hash1 = crypto.createHash('md5').update('test').digest('hex');

// SHA-256 - should be detected as LOW/MEDIUM risk
const hash2 = crypto.createHash('sha256').update('test').digest('hex');

// AES-256 - should be detected as quantum-safe
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

console.log(hash1, hash2);
