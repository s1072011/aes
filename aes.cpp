#include "aes.h"

Aes::Aes(std::unique_ptr<AesStrategy> aes_algorithm) { setStrategy(std::move(aes_algorithm)); }

ByteArray Aes::Encrypt(ByteArray plaintext, ByteArray key, AesKeyLengthOptions option,
                       const ByteArray& iv) const {
  return aes_algorithm_->Encrypt(std::move(plaintext), std::move(key), option, iv);
}

ByteArray Aes::Decrypt(ByteArray ciphertext, ByteArray key, AesKeyLengthOptions option,
                       const ByteArray& iv) const {
  return aes_algorithm_->Decrypt(std::move(ciphertext), std::move(key), option, iv);
}

void Aes::setStrategy(std::unique_ptr<AesStrategy> aes_algorithm) {
  aes_algorithm_.reset(aes_algorithm.release());
}
