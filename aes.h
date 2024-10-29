#ifndef AES_H
#define AES_H

#include <memory>

#include "aes_impls.h"

class Aes {
 public:
  explicit Aes(std::unique_ptr<AesStrategy> aes_algorithm = std::make_unique<AesECB>());

  ByteArray Encrypt(ByteArray plaintext, ByteArray key, AesKeyLengthOptions option,
                    const ByteArray& iv = ByteArray(16)) const;
  ByteArray Decrypt(ByteArray ciphertext, ByteArray key, AesKeyLengthOptions option,
                    const ByteArray& iv = ByteArray(16)) const;

  void setStrategy(std::unique_ptr<AesStrategy> aes_strategy);

 private:
  std::unique_ptr<AesStrategy> aes_algorithm_ = nullptr;
};

#endif
