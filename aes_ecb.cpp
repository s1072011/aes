#include "aes_impls.h"

ByteArray AesECB::Encrypt(ByteArray &&plaintext, ByteArray &&key, AesKeyLengthOptions option,
                          const ByteArray &iv = {}) {
  Init(option);
  KeyExpansion(std::move(key));
  CheckPlaintextLength(plaintext.size());
  AddPaddingForPlaintext(plaintext);

  auto block_count = plaintext.size() / BLOCK_SIZE_IN_BYTES;
  auto pt_word_arr = ConvertByteArrayToWordArray(plaintext);

  ParallelEncryption(&AesECB::Cipher, pt_word_arr.get(), block_count);

  round_keys_.reset();

  return ConvertWordArrayToByteArray(std::move(pt_word_arr), block_count * BLOCK_SIZE_IN_WORDS);
}

ByteArray AesECB::Decrypt(ByteArray &&ciphertext, ByteArray &&key, AesKeyLengthOptions option,
                          const ByteArray &iv = {}) {
  Init(option);
  KeyExpansion(std::move(key));
  CheckCiphertextLength(ciphertext.size());

  auto block_count = ciphertext.size() / BLOCK_SIZE_IN_BYTES;
  auto ct_word_arr = ConvertByteArrayToWordArray(ciphertext);

  ParallelEncryption(&AesECB::InvCipher, ct_word_arr.get(), block_count);

  round_keys_.reset();

  auto result =
      ConvertWordArrayToByteArray(std::move(ct_word_arr), block_count * BLOCK_SIZE_IN_WORDS);
  RemovePadding(result);

  return result;
}
