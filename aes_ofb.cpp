#include "aes_impls.h"

ByteArray AesOFB::Encrypt(ByteArray &&plaintext, ByteArray &&key, AesKeyLengthOptions option,
                          const ByteArray &iv) {
  Init(option);
  KeyExpansion(std::move(key));
  CheckPlaintextLength(plaintext.size());
  AddPaddingForPlaintext(plaintext);

  auto block_count = plaintext.size() / BLOCK_SIZE_IN_BYTES;
  auto pt_word_arr = ConvertByteArrayToWordArray(plaintext);

  auto priv_block = ConvertByteArrayToWordArray(iv);

  for (size_t i = 0; i < block_count; i++) {
    auto offset = i * BLOCK_SIZE_IN_WORDS;

    Cipher(priv_block.get());

    std::memcpy(pt_word_arr.get() + offset,
                XorWordArray(priv_block.get(), pt_word_arr.get() + offset).get(),
                BLOCK_SIZE_IN_BYTES);
  }

  round_keys_.reset();

  return ConvertWordArrayToByteArray(std::move(pt_word_arr), block_count * BLOCK_SIZE_IN_WORDS);
}

ByteArray AesOFB::Decrypt(ByteArray &&ciphertext, ByteArray &&key, AesKeyLengthOptions option,
                          const ByteArray &iv) {
  Init(option);
  KeyExpansion(std::move(key));
  CheckCiphertextLength(ciphertext.size());

  auto ct_word_arr = ConvertByteArrayToWordArray(ciphertext);
  auto block_count = ciphertext.size() / BLOCK_SIZE_IN_BYTES;

  auto priv_block = ConvertByteArrayToWordArray(iv);

  for (size_t i = 0; i < block_count; i++) {
    auto offset = i * BLOCK_SIZE_IN_WORDS;

    Cipher(priv_block.get());

    std::memcpy(ct_word_arr.get() + offset,
                XorWordArray(priv_block.get(), ct_word_arr.get() + offset).get(),
                BLOCK_SIZE_IN_BYTES);
  }

  round_keys_.reset();

  auto result =
      ConvertWordArrayToByteArray(std::move(ct_word_arr), block_count * BLOCK_SIZE_IN_WORDS);
  RemovePadding(result);

  return result;
}
