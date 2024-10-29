#include <thread>

#include "aes_impls.h"

ByteArray AesCTR::Encrypt(ByteArray &&plaintext, ByteArray &&key, AesKeyLengthOptions option,
                          const ByteArray &iv = {}) {
  Init(option);
  KeyExpansion(std::move(key));
  CheckPlaintextLength(plaintext.size());
  AddPaddingForPlaintext(plaintext);

  auto block_count = plaintext.size() / BLOCK_SIZE_IN_BYTES;
  auto pt_word_arr = ConvertByteArrayToWordArray(plaintext);

  auto counter = ConvertByteArrayToWordArray(iv);

  ParallelEncryption(&AesCTR::Cipher, pt_word_arr.get(), counter.get(), block_count);

  round_keys_.reset();

  return ConvertWordArrayToByteArray(std::move(pt_word_arr), block_count * BLOCK_SIZE_IN_WORDS);
}

ByteArray AesCTR::Decrypt(ByteArray &&ciphertext, ByteArray &&key, AesKeyLengthOptions option,
                          const ByteArray &iv = {}) {
  Init(option);
  KeyExpansion(std::move(key));
  CheckCiphertextLength(ciphertext.size());

  auto block_count = ciphertext.size() / BLOCK_SIZE_IN_BYTES;
  auto ct_word_arr = ConvertByteArrayToWordArray(ciphertext);

  auto counter = ConvertByteArrayToWordArray(iv);

  ParallelEncryption(&AesCTR::InvCipher, ct_word_arr.get(), counter.get(), block_count);

  round_keys_.reset();

  auto result =
      ConvertWordArrayToByteArray(std::move(ct_word_arr), block_count * BLOCK_SIZE_IN_WORDS);
  RemovePadding(result);

  return result;
}

void AesCTR::ParallelEncryption(void (AesStrategy::*CipherFunction)(Word *) const,
                                Word *block_begin, const Word *iv, size_t block_count) const {
  auto cpu_core_count = std::thread::hardware_concurrency();

  auto Add = [](const Word *arr, size_t value) {
    Byte carry = 0;
    Word summand[4];
    std::memcpy(summand, arr, BLOCK_SIZE_IN_BYTES);
    Word addend[4] = {0, 0, static_cast<Word>(value >> 16), static_cast<Word>(value)};

    for (int i = 3; i >= 0; i--) {
      summand[i] += addend[i];
    }
  };

  auto ProcessBlocks = [this, CipherFunction, block_begin](size_t start_index, size_t end_index) {
    for (auto i = start_index; i < end_index; i++) {
      auto offset = i * BLOCK_SIZE_IN_WORDS;
      (this->*CipherFunction)(block_begin + offset);
    }
  };

  if (cpu_core_count < 2 || block_count < 5120) {
    ProcessBlocks(0, block_count);
  } else {
    std::vector<std::thread> parallel_threads;
    int parallel_threads_count = cpu_core_count - 1;
    auto block_per_thread = block_count / parallel_threads_count;

    for (int i = 0; i < parallel_threads_count - 1; i++) {
      parallel_threads.push_back(
          std::thread(ProcessBlocks, block_per_thread * i, block_per_thread * (i + 1)));
    }

    parallel_threads.push_back(
        std::thread(ProcessBlocks, block_per_thread * (parallel_threads_count - 1), block_count));

    for (auto &th : parallel_threads) {
      th.join();
    }
  }
}
