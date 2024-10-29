#include "aes_strategy.h"

#include <cstring>
#include <exception>
#include <functional>
#include <string>
#include <thread>

#define ROTWORD(w) w = ((w) >> 24 | (w) << 8)
#define SHIFT_2(w) w = ((w) << 16 | (((w) >> 16) & 0xffff))
#define LEFT_SHIFT_1(w) ROTWORD(w)
#define RIGHT_SHIFT_1(w) w = (w << 24 | w >> 8)
#define LEFT_SHIFT_3(w) RIGHT_SHIFT_1(w)
#define RIGHT_SHIFT_3(w) LEFT_SHIFT_1(w)

#define BYTE0(w) Byte((w) >> 24)
#define BYTE1(w) Byte((w) >> 16)
#define BYTE2(w) Byte((w) >> 8)
#define BYTE3(w) Byte((w))

#define MAKE_WORD(byte0, byte1, byte2, byte3) \
  (((Word)(byte0) << 24) | ((Word)(byte1) << 16) | ((Word)(byte2) << 8) | Word(byte3))
#define REVERSE_WORD(w) w = MAKE_WORD(BYTE3(w), BYTE2(w), BYTE1(w), BYTE0(w))

class InputException : public std::exception {
 public:
  explicit InputException(const std::string &msg) : msg_(msg) {};

  const char *what() const noexcept override { return msg_.c_str(); }

 private:
  std::string msg_;
};

void AesStrategy::Init(AesKeyLengthOptions option) {
  switch (option) {
    case AesKeyLengthOptions::kBit_128:
      round_count_ = 10;
      key_length_in_bytes_ = 16;
      break;
    case AesKeyLengthOptions::kBit_192:
      round_count_ = 12;
      key_length_in_bytes_ = 24;
      break;
    case AesKeyLengthOptions::kBit_256:
      round_count_ = 14;
      key_length_in_bytes_ = 32;
      break;
  }
}

void AesStrategy::Cipher(Word state[BLOCK_SIZE_IN_WORDS]) const {
  Transpose(state);

  Byte i_rk = 0;
  AddRoundKey(state, round_keys_.get());

  for (i_rk = 1; i_rk < round_count_; i_rk++) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, round_keys_.get() + i_rk * BLOCK_SIZE_IN_WORDS);
  }

  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(state, round_keys_.get() + i_rk * BLOCK_SIZE_IN_WORDS);

  Transpose(state);
}

void AesStrategy::InvCipher(Word state[BLOCK_SIZE_IN_WORDS]) const {
  Transpose(state);

  auto i_rk = round_count_;
  AddRoundKey(state, round_keys_.get() + i_rk * BLOCK_SIZE_IN_WORDS);

  for (i_rk = round_count_ - 1; i_rk > 0; i_rk--) {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, round_keys_.get() + i_rk * BLOCK_SIZE_IN_WORDS);
    InvMixColumns(state);
  }

  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(state, round_keys_.get() + i_rk * BLOCK_SIZE_IN_WORDS);

  Transpose(state);
}

void AesStrategy::SubBytes(Word state[BLOCK_SIZE_IN_WORDS]) const {
  for (Byte i = 0; i < BLOCK_SIZE_IN_WORDS; i++) {
    Byte temp[WORD_SIZE] = {BYTE0(state[i]), BYTE1(state[i]), BYTE2(state[i]), BYTE3(state[i])};
    temp[0] = kSBox[(temp[0] & 0xf0) + (temp[0] & 0xf)];
    temp[1] = kSBox[(temp[1] & 0xf0) + (temp[1] & 0xf)];
    temp[2] = kSBox[(temp[2] & 0xf0) + (temp[2] & 0xf)];
    temp[3] = kSBox[(temp[3] & 0xf0) + (temp[3] & 0xf)];
    state[i] = MAKE_WORD(temp[0], temp[1], temp[2], temp[3]);
  }
}

void AesStrategy::InvSubBytes(Word state[BLOCK_SIZE_IN_WORDS]) const {
  for (Byte i = 0; i < BLOCK_SIZE_IN_WORDS; i++) {
    Byte temp[WORD_SIZE] = {BYTE0(state[i]), BYTE1(state[i]), BYTE2(state[i]), BYTE3(state[i])};
    temp[0] = kInverseSBox[(temp[0] & 0xf0) + (temp[0] & 0xf)];
    temp[1] = kInverseSBox[(temp[1] & 0xf0) + (temp[1] & 0xf)];
    temp[2] = kInverseSBox[(temp[2] & 0xf0) + (temp[2] & 0xf)];
    temp[3] = kInverseSBox[(temp[3] & 0xf0) + (temp[3] & 0xf)];
    state[i] = MAKE_WORD(temp[0], temp[1], temp[2], temp[3]);
  }
}

void AesStrategy::ShiftRows(Word state[BLOCK_SIZE_IN_WORDS]) const {
  LEFT_SHIFT_1(state[1]);
  SHIFT_2(state[2]);
  LEFT_SHIFT_3(state[3]);
}

void AesStrategy::InvShiftRows(Word state[BLOCK_SIZE_IN_WORDS]) const {
  RIGHT_SHIFT_1(state[1]);
  SHIFT_2(state[2]);
  RIGHT_SHIFT_3(state[3]);
}

void AesStrategy::MixColumns(Word state[BLOCK_SIZE_IN_WORDS]) const {
  Word temp[BLOCK_SIZE_IN_WORDS];
  std::memcpy(temp, state, BLOCK_SIZE_IN_BYTES);

  state[0] =
      MAKE_WORD(kMul_2[BYTE0(temp[0])] ^ kMul_3[BYTE0(temp[1])] ^ BYTE0(temp[2]) ^ BYTE0(temp[3]),
                kMul_2[BYTE1(temp[0])] ^ kMul_3[BYTE1(temp[1])] ^ BYTE1(temp[2]) ^ BYTE1(temp[3]),
                kMul_2[BYTE2(temp[0])] ^ kMul_3[BYTE2(temp[1])] ^ BYTE2(temp[2]) ^ BYTE2(temp[3]),
                kMul_2[BYTE3(temp[0])] ^ kMul_3[BYTE3(temp[1])] ^ BYTE3(temp[2]) ^ BYTE3(temp[3]));

  state[1] =
      MAKE_WORD(BYTE0(temp[0]) ^ kMul_2[BYTE0(temp[1])] ^ kMul_3[BYTE0(temp[2])] ^ BYTE0(temp[3]),
                BYTE1(temp[0]) ^ kMul_2[BYTE1(temp[1])] ^ kMul_3[BYTE1(temp[2])] ^ BYTE1(temp[3]),
                BYTE2(temp[0]) ^ kMul_2[BYTE2(temp[1])] ^ kMul_3[BYTE2(temp[2])] ^ BYTE2(temp[3]),
                BYTE3(temp[0]) ^ kMul_2[BYTE3(temp[1])] ^ kMul_3[BYTE3(temp[2])] ^ BYTE3(temp[3]));

  state[2] =
      MAKE_WORD(BYTE0(temp[0]) ^ BYTE0(temp[1]) ^ kMul_2[BYTE0(temp[2])] ^ kMul_3[BYTE0(temp[3])],
                BYTE1(temp[0]) ^ BYTE1(temp[1]) ^ kMul_2[BYTE1(temp[2])] ^ kMul_3[BYTE1(temp[3])],
                BYTE2(temp[0]) ^ BYTE2(temp[1]) ^ kMul_2[BYTE2(temp[2])] ^ kMul_3[BYTE2(temp[3])],
                BYTE3(temp[0]) ^ BYTE3(temp[1]) ^ kMul_2[BYTE3(temp[2])] ^ kMul_3[BYTE3(temp[3])]);

  state[3] =
      MAKE_WORD(kMul_3[BYTE0(temp[0])] ^ BYTE0(temp[1]) ^ BYTE0(temp[2]) ^ kMul_2[BYTE0(temp[3])],
                kMul_3[BYTE1(temp[0])] ^ BYTE1(temp[1]) ^ BYTE1(temp[2]) ^ kMul_2[BYTE1(temp[3])],
                kMul_3[BYTE2(temp[0])] ^ BYTE2(temp[1]) ^ BYTE2(temp[2]) ^ kMul_2[BYTE2(temp[3])],
                kMul_3[BYTE3(temp[0])] ^ BYTE3(temp[1]) ^ BYTE3(temp[2]) ^ kMul_2[BYTE3(temp[3])]);
}

void AesStrategy::InvMixColumns(Word state[BLOCK_SIZE_IN_WORDS]) const {
  Word temp[BLOCK_SIZE_IN_WORDS];
  std::memcpy(temp, state, BLOCK_SIZE_IN_BYTES);

  state[0] = MAKE_WORD(kMul_14[BYTE0(temp[0])] ^ kMul_11[BYTE0(temp[1])] ^ kMul_13[BYTE0(temp[2])] ^
                           kMul_9[BYTE0(temp[3])],
                       kMul_14[BYTE1(temp[0])] ^ kMul_11[BYTE1(temp[1])] ^ kMul_13[BYTE1(temp[2])] ^
                           kMul_9[BYTE1(temp[3])],
                       kMul_14[BYTE2(temp[0])] ^ kMul_11[BYTE2(temp[1])] ^ kMul_13[BYTE2(temp[2])] ^
                           kMul_9[BYTE2(temp[3])],
                       kMul_14[BYTE3(temp[0])] ^ kMul_11[BYTE3(temp[1])] ^ kMul_13[BYTE3(temp[2])] ^
                           kMul_9[BYTE3(temp[3])]);

  state[1] = MAKE_WORD(kMul_9[BYTE0(temp[0])] ^ kMul_14[BYTE0(temp[1])] ^ kMul_11[BYTE0(temp[2])] ^
                           kMul_13[BYTE0(temp[3])],
                       kMul_9[BYTE1(temp[0])] ^ kMul_14[BYTE1(temp[1])] ^ kMul_11[BYTE1(temp[2])] ^
                           kMul_13[BYTE1(temp[3])],
                       kMul_9[BYTE2(temp[0])] ^ kMul_14[BYTE2(temp[1])] ^ kMul_11[BYTE2(temp[2])] ^
                           kMul_13[BYTE2(temp[3])],
                       kMul_9[BYTE3(temp[0])] ^ kMul_14[BYTE3(temp[1])] ^ kMul_11[BYTE3(temp[2])] ^
                           kMul_13[BYTE3(temp[3])]);

  state[2] = MAKE_WORD(kMul_13[BYTE0(temp[0])] ^ kMul_9[BYTE0(temp[1])] ^ kMul_14[BYTE0(temp[2])] ^
                           kMul_11[BYTE0(temp[3])],
                       kMul_13[BYTE1(temp[0])] ^ kMul_9[BYTE1(temp[1])] ^ kMul_14[BYTE1(temp[2])] ^
                           kMul_11[BYTE1(temp[3])],
                       kMul_13[BYTE2(temp[0])] ^ kMul_9[BYTE2(temp[1])] ^ kMul_14[BYTE2(temp[2])] ^
                           kMul_11[BYTE2(temp[3])],
                       kMul_13[BYTE3(temp[0])] ^ kMul_9[BYTE3(temp[1])] ^ kMul_14[BYTE3(temp[2])] ^
                           kMul_11[BYTE3(temp[3])]);

  state[3] = MAKE_WORD(kMul_11[BYTE0(temp[0])] ^ kMul_13[BYTE0(temp[1])] ^ kMul_9[BYTE0(temp[2])] ^
                           kMul_14[BYTE0(temp[3])],
                       kMul_11[BYTE1(temp[0])] ^ kMul_13[BYTE1(temp[1])] ^ kMul_9[BYTE1(temp[2])] ^
                           kMul_14[BYTE1(temp[3])],
                       kMul_11[BYTE2(temp[0])] ^ kMul_13[BYTE2(temp[1])] ^ kMul_9[BYTE2(temp[2])] ^
                           kMul_14[BYTE2(temp[3])],
                       kMul_11[BYTE3(temp[0])] ^ kMul_13[BYTE3(temp[1])] ^ kMul_9[BYTE3(temp[2])] ^
                           kMul_14[BYTE3(temp[3])]);
}

void AesStrategy::KeyExpansion(ByteArray &&byte_key_arr) {
  auto key_length = byte_key_arr.size();
  if (key_length > 32) {
    throw InputException("The length of the input key exceeds 256 bits.");
  } else if (key_length > key_length_in_bytes_) {
    throw InputException(
        "The length of the input key exceeds the preset length. The key length "
        "is " +
        std::to_string(key_length * 8) + " bits, while the preset length is " +
        std::to_string(key_length_in_bytes_ * 8) + " bits.");
  } else if (key_length < key_length_in_bytes_) {
    auto padding = Byte(key_length_in_bytes_ - key_length);
    byte_key_arr.resize(key_length_in_bytes_, padding);
  } else if (key_length == 0) {
    byte_key_arr.resize(key_length_in_bytes_, 0);
  }

  auto word_key_arr = CREATE_WORD_ARRAY(key_length_in_bytes_ / WORD_SIZE);

  Byte key_length_in_words = key_length_in_bytes_ / WORD_SIZE;
  for (Byte i = 0, j = 0; i < key_length_in_words; i++, j += 4) {
    word_key_arr[i] =
        MAKE_WORD(byte_key_arr[j], byte_key_arr[j + 1], byte_key_arr[j + 2], byte_key_arr[j + 3]);
  }

  auto rk_size_in_words = BLOCK_SIZE_IN_WORDS * (round_count_ + 1);
  round_keys_ = CREATE_WORD_ARRAY(rk_size_in_words);

  Byte i_rk = 0;

  while (i_rk < key_length_in_words) {
    round_keys_[i_rk] = word_key_arr[i_rk];
    i_rk++;
  }

  Word temp;

  while (i_rk < rk_size_in_words) {
    temp = round_keys_[i_rk - 1];

    if (i_rk % key_length_in_words == 0) {
      ROTWORD(temp);
      SubWord(temp);
      temp ^= kRCon[i_rk / key_length_in_words - 1];
    } else if (key_length_in_words > 6 && (i_rk % key_length_in_words == 4)) {
      SubWord(temp);
    }

    round_keys_[i_rk] = round_keys_[i_rk - key_length_in_words] ^ temp;
    i_rk++;
  }

  for (int i = 0; i < (round_count_ + 1); i++) {
    Transpose(round_keys_.get() + i * BLOCK_SIZE_IN_WORDS);
  }
}

void AesStrategy::AddRoundKey(Word state[BLOCK_SIZE_IN_WORDS],
                              const Word round_key[BLOCK_SIZE_IN_WORDS]) const {
  for (Byte i = 0; i < BLOCK_SIZE_IN_WORDS; i++) {
    state[i] ^= round_key[i];
  }
}

void AesStrategy::AddPaddingForPlaintext(ByteArray &plaintext) const {
  Byte padding = 0;
  auto temp_length = plaintext.size();
  if (temp_length % BLOCK_SIZE_IN_BYTES != 0) {
    padding = BLOCK_SIZE_IN_BYTES - temp_length % BLOCK_SIZE_IN_BYTES;

    temp_length += padding;
    if (padding == 1) {
      temp_length += BLOCK_SIZE_IN_BYTES;
      plaintext.resize(temp_length, 1);
      plaintext[temp_length - BLOCK_SIZE_IN_BYTES - 1] = BLOCK_SIZE_IN_BYTES - 1;
    } else {
      plaintext.resize(temp_length, padding);
      plaintext[temp_length - padding] = BLOCK_SIZE_IN_BYTES - padding;
    }
  }
}

void AesStrategy::RemovePadding(ByteArray &text) const {
  auto padding = text[text.size() - 1];
  if (padding == 0 || padding > 0xf) {
    return;
  } else if (padding == 1) {
    for (auto i = text.size() - 1; i > text.size() - BLOCK_SIZE_IN_BYTES; i--) {
      if (text[i] != 1) {
        return;
      }
    }
    if (text[text.size() - BLOCK_SIZE_IN_BYTES - 1] == BLOCK_SIZE_IN_BYTES - 1) {
      text.resize(text.size() - BLOCK_SIZE_IN_BYTES - 1);
    }
  } else {
    for (size_t i = text.size() - 1; i > text.size() - padding; i--) {
      if (text[i] != padding) {
        return;
      }
    }
    if (text[text.size() - padding] == BLOCK_SIZE_IN_BYTES - padding) {
      text.resize(text.size() - padding);
    }
  }
}

void AesStrategy::Transpose(Word block[BLOCK_SIZE_IN_WORDS]) const {
  Word temp[BLOCK_SIZE_IN_WORDS]{};

  temp[0] = MAKE_WORD(BYTE0(block[0]), BYTE0(block[1]), BYTE0(block[2]), BYTE0(block[3]));
  temp[1] = MAKE_WORD(BYTE1(block[0]), BYTE1(block[1]), BYTE1(block[2]), BYTE1(block[3]));
  temp[2] = MAKE_WORD(BYTE2(block[0]), BYTE2(block[1]), BYTE2(block[2]), BYTE2(block[3]));
  temp[3] = MAKE_WORD(BYTE3(block[0]), BYTE3(block[1]), BYTE3(block[2]), BYTE3(block[3]));

  std::memcpy(block, temp, BLOCK_SIZE_IN_BYTES);
}

void AesStrategy::SubWord(Word &w) const {
  Byte temp[WORD_SIZE] = {BYTE0(w), BYTE1(w), BYTE2(w), BYTE3(w)};
  temp[0] = kSBox[(temp[0] & 0xf0) + (temp[0] & 0xf)];
  temp[1] = kSBox[(temp[1] & 0xf0) + (temp[1] & 0xf)];
  temp[2] = kSBox[(temp[2] & 0xf0) + (temp[2] & 0xf)];
  temp[3] = kSBox[(temp[3] & 0xf0) + (temp[3] & 0xf)];
  w = MAKE_WORD(temp[0], temp[1], temp[2], temp[3]);
}

WordArray AesStrategy::ConvertByteArrayToWordArray(const ByteArray &byte_arr) const {
  auto word_arr_size = byte_arr.size() / WORD_SIZE;
  auto word_arr = CREATE_WORD_ARRAY(word_arr_size);
  for (size_t i = 0, j = 0; i < word_arr_size; i++, j += BLOCK_SIZE_IN_WORDS) {
    word_arr[i] = MAKE_WORD(byte_arr[j], byte_arr[j + 1], byte_arr[j + 2], byte_arr[j + 3]);
  }
  return word_arr;
}

ByteArray AesStrategy::ConvertWordArrayToByteArray(WordArray word_arr, size_t size) const {
  ByteArray byte_arr(size * WORD_SIZE);
  for (size_t i = 0, j = 0; i < size; i++, j += WORD_SIZE) {
    byte_arr[j] = BYTE0(word_arr[i]);
    byte_arr[j + 1] = BYTE1(word_arr[i]);
    byte_arr[j + 2] = BYTE2(word_arr[i]);
    byte_arr[j + 3] = BYTE3(word_arr[i]);
  }
  return byte_arr;
}

WordArray AesStrategy::XorWordArray(const Word block1[BLOCK_SIZE_IN_WORDS],
                                    const Word block2[BLOCK_SIZE_IN_WORDS]) const {
  auto result = CREATE_WORD_ARRAY(BLOCK_SIZE_IN_WORDS);
  for (Byte i = 0; i < BLOCK_SIZE_IN_WORDS; i++) {
    result[i] = block1[i] ^ block2[i];
  }
  return result;
}

void AesStrategy::CheckPlaintextLength(size_t length) const {
  if (length == 0) {
    throw InputException("Plaintext can't be null.");
  }
}

void AesStrategy::CheckCiphertextLength(size_t length) const {
  if (length == 0) {
    throw InputException("Ciphertext can't be null.");
  }
  if (length % BLOCK_SIZE_IN_BYTES != 0) {
    throw InputException("The length of ciphertext must be a multiple of 16 bytes.");
  }
}

void AesStrategy::ParallelEncryption(void (AesStrategy::*CipherFunction)(Word *) const,
                                     Word *block_begin, size_t block_count) const {
  auto cpu_core_count = std::thread::hardware_concurrency();

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
