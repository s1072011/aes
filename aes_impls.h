#ifndef AES_IMPLS_H
#define AES_IMPLS_H

#include <cstring>

#include "aes_strategy.h"

class AesECB : public AesStrategy {
 public:
  virtual ByteArray Encrypt(ByteArray &&plaintext, ByteArray &&key, AesKeyLengthOptions option,
                            const ByteArray &iv) override;
  virtual ByteArray Decrypt(ByteArray &&ciphertext, ByteArray &&key, AesKeyLengthOptions option,
                            const ByteArray &iv) override;
  AesECB() = default;
  ~AesECB() = default;
};

class AesCBC : public AesStrategy {
 public:
  virtual ByteArray Encrypt(ByteArray &&plaintext, ByteArray &&key, AesKeyLengthOptions option,
                            const ByteArray &iv) override;
  virtual ByteArray Decrypt(ByteArray &&ciphertext, ByteArray &&key, AesKeyLengthOptions option,
                            const ByteArray &iv) override;
  AesCBC() = default;
  ~AesCBC() = default;
};

class AesCFB : public AesStrategy {
 public:
  virtual ByteArray Encrypt(ByteArray &&plaintext, ByteArray &&key, AesKeyLengthOptions option,
                            const ByteArray &iv) override;
  virtual ByteArray Decrypt(ByteArray &&ciphertext, ByteArray &&key, AesKeyLengthOptions option,
                            const ByteArray &iv) override;
  AesCFB() = default;
  ~AesCFB() = default;
};

class AesOFB : public AesStrategy {
 public:
  virtual ByteArray Encrypt(ByteArray &&plaintext, ByteArray &&key, AesKeyLengthOptions option,
                            const ByteArray &iv) override;
  virtual ByteArray Decrypt(ByteArray &&ciphertext, ByteArray &&key, AesKeyLengthOptions option,
                            const ByteArray &iv) override;
  AesOFB() = default;
  ~AesOFB() = default;
};

class AesCTR : public AesStrategy {
 public:
  virtual ByteArray Encrypt(ByteArray &&plaintext, ByteArray &&key, AesKeyLengthOptions option,
                            const ByteArray &iv) override;
  virtual ByteArray Decrypt(ByteArray &&ciphertext, ByteArray &&key, AesKeyLengthOptions option,
                            const ByteArray &iv) override;
  AesCTR() = default;
  ~AesCTR() = default;

  void ParallelEncryption(void (AesStrategy::*CipherFunction)(Word *) const, Word *block_begin,
                          const Word *iv, size_t block_count) const;
};

#endif  // AES_IMPLS_H
