import { describe, it, expect, beforeEach } from '@jest/globals';
import { DeterministicAES } from '../src/crypto/deterministic-aes.js';

describe('DeterministicAES', () => {
  let dek: Buffer;
  const userId = 'user123';
  const plaintext = 'john.doe@example.com';

  beforeEach(() => {
    dek = DeterministicAES.generateRandomDEK();
  });

  describe('encrypt', () => {
    it('should encrypt plaintext and return base64 ciphertext', () => {
      const result = DeterministicAES.encrypt(plaintext, userId, dek);

      expect(result.ciphertext).toBeDefined();
      expect(result.userId).toBe(userId);
      expect(result.timestamp).toBeDefined();
      expect(result.ciphertext).toMatch(/^[A-Za-z0-9+/=]+$/); // Base64
    });

    it('should produce deterministic ciphertext (same input = same output)', () => {
      const result1 = DeterministicAES.encrypt(plaintext, userId, dek);
      const result2 = DeterministicAES.encrypt(plaintext, userId, dek);

      expect(result1.ciphertext).toBe(result2.ciphertext);
    });

    it('should produce different ciphertexts for different userIds', () => {
      const result1 = DeterministicAES.encrypt(plaintext, 'user1', dek);
      const result2 = DeterministicAES.encrypt(plaintext, 'user2', dek);

      expect(result1.ciphertext).not.toBe(result2.ciphertext);
    });

    it('should produce different ciphertexts for different plaintexts', () => {
      const result1 = DeterministicAES.encrypt('plaintext1', userId, dek);
      const result2 = DeterministicAES.encrypt('plaintext2', userId, dek);

      expect(result1.ciphertext).not.toBe(result2.ciphertext);
    });

    it('should produce different ciphertexts for different DEKs', () => {
      const dek1 = DeterministicAES.generateRandomDEK();
      const dek2 = DeterministicAES.generateRandomDEK();

      const result1 = DeterministicAES.encrypt(plaintext, userId, dek1);
      const result2 = DeterministicAES.encrypt(plaintext, userId, dek2);

      expect(result1.ciphertext).not.toBe(result2.ciphertext);
    });

    it('should throw error with invalid DEK size', () => {
      const invalidDek = Buffer.alloc(16); // Wrong size

      expect(() => {
        DeterministicAES.encrypt(plaintext, userId, invalidDek);
      }).toThrow('DEK must be 32 bytes');
    });
  });

  describe('decrypt', () => {
    it('should decrypt ciphertext back to plaintext', () => {
      const encrypted = DeterministicAES.encrypt(plaintext, userId, dek);
      const decrypted = DeterministicAES.decrypt(
        encrypted.ciphertext,
        userId,
        dek
      );

      expect(decrypted.plaintext).toBe(plaintext);
      expect(decrypted.userId).toBe(userId);
      expect(decrypted.timestamp).toBeDefined();
    });

    it('should fail decryption with different userId (GCM AAD validation)', () => {
      const encrypted = DeterministicAES.encrypt(plaintext, 'user1', dek);

      expect(() => {
        DeterministicAES.decrypt(encrypted.ciphertext, 'user2', dek);
      }).toThrow();
    });

    it('should fail decryption with different DEK', () => {
      const encrypted = DeterministicAES.encrypt(plaintext, userId, dek);
      const differentDek = DeterministicAES.generateRandomDEK();

      expect(() => {
        DeterministicAES.decrypt(encrypted.ciphertext, userId, differentDek);
      }).toThrow();
    });

    it('should fail decryption with tampered ciphertext', () => {
      const encrypted = DeterministicAES.encrypt(plaintext, userId, dek);
      const tampered = Buffer.from(encrypted.ciphertext, 'base64');
      tampered[0] ^= 0xff; // Flip bits in first byte

      expect(() => {
        DeterministicAES.decrypt(tampered.toString('base64'), userId, dek);
      }).toThrow();
    });

    it('should fail decryption with invalid base64 ciphertext', () => {
      expect(() => {
        DeterministicAES.decrypt('invalid!@#$', userId, dek);
      }).toThrow();
    });

    it('should throw error with invalid DEK size', () => {
      const encrypted = DeterministicAES.encrypt(plaintext, userId, dek);
      const invalidDek = Buffer.alloc(16);

      expect(() => {
        DeterministicAES.decrypt(encrypted.ciphertext, userId, invalidDek);
      }).toThrow('DEK must be 32 bytes');
    });
  });

  describe('generateDeterministicIV', () => {
    it('should generate 12-byte IV from userId', () => {
      const iv = DeterministicAES.generateDeterministicIV('user123');

      expect(Buffer.isBuffer(iv)).toBe(true);
      expect(iv.length).toBe(12);
    });

    it('should produce same IV for same userId (deterministic)', () => {
      const iv1 = DeterministicAES.generateDeterministicIV('user123');
      const iv2 = DeterministicAES.generateDeterministicIV('user123');

      expect(iv1.equals(iv2)).toBe(true);
    });

    it('should produce different IVs for different userIds', () => {
      const iv1 = DeterministicAES.generateDeterministicIV('user1');
      const iv2 = DeterministicAES.generateDeterministicIV('user2');

      expect(iv1.equals(iv2)).toBe(false);
    });
  });

  describe('generateRandomDEK', () => {
    it('should generate 32-byte DEK', () => {
      const dek = DeterministicAES.generateRandomDEK();

      expect(Buffer.isBuffer(dek)).toBe(true);
      expect(dek.length).toBe(32);
    });

    it('should generate different DEKs on each call', () => {
      const dek1 = DeterministicAES.generateRandomDEK();
      const dek2 = DeterministicAES.generateRandomDEK();

      expect(dek1.equals(dek2)).toBe(false);
    });
  });

  describe('round-trip encryption/decryption', () => {
    it('should successfully decrypt all types of plaintexts', () => {
      const testCases = [
        'simple text',
        'user@example.com',
        'special!@#$%^&*()',
        '日本語テキスト', // Japanese
        'عربي', // Arabic
        '🔐🗝️🔑', // Emojis
        '', // Empty string
        'a'.repeat(10000), // Large payload
      ];

      testCases.forEach((text) => {
        const encrypted = DeterministicAES.encrypt(text, userId, dek);
        const decrypted = DeterministicAES.decrypt(
          encrypted.ciphertext,
          userId,
          dek
        );

        expect(decrypted.plaintext).toBe(text);
      });
    });
  });
});
