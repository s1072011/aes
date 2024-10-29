#include <chrono>
#include <cstring>
#include <exception>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <vector>

#include "aes.h"

int main(int argc, char* argv[]) {
  std::string in_path = "";
  std::string out_path = "";
  std::string key_path = "";
  std::string iv_path = "";

  AesKeyLengthOptions option = AesKeyLengthOptions::kBit_256;
  Aes aes;

  if (argc >= 5) {
    if ((std::string)argv[1] != "enc" && (std::string)argv[1] != "dec") {
      std::cerr << "Please enter \"enc\" or \"dec\" as first argument.\n";
      exit(-1);
    }

    out_path = ((std::string)argv[1] == "enc") ? "./ciphertext.out" : "./plaintext.out";

    if ((std::string)argv[2] == "ecb") {
      aes.setStrategy(std::make_unique<AesECB>());
    } else if ((std::string)argv[2] == "cbc") {
      aes.setStrategy(std::make_unique<AesCBC>());
    } else if ((std::string)argv[2] == "cfb") {
      aes.setStrategy(std::make_unique<AesCFB>());
    } else if ((std::string)argv[2] == "ofb") {
      aes.setStrategy(std::make_unique<AesOFB>());
    } else if ((std::string)argv[2] == "ctr") {
      aes.setStrategy(std::make_unique<AesCTR>());
    } else {
      std::cerr << "The mode \"" << argv[2] << "\" entered is unsupported or invalid.\n";
      exit(-1);
    }

    in_path = std::string(argv[3]);
    key_path = std::string(argv[4]);

    switch (atoi(argv[5])) {
      case 128:
        option = AesKeyLengthOptions::kBit_128;
        break;
      case 192:
        option = AesKeyLengthOptions::kBit_192;
        break;
      case 256:
        option = AesKeyLengthOptions::kBit_256;
        break;
      case 0:
        option = AesKeyLengthOptions::kBit_256;
        break;
      default:
        std::cerr << "Warning: Invalid key length(was being set to 256).\n";
        option = AesKeyLengthOptions::kBit_256;
    }

    if (argc == 7) {
      iv_path = std::string(argv[6]);
    }
  } else {
    std::cerr << "\t ./aes [mode:enc/dec] "
              << "[mode:ecb/cbc...] "
              << "<plaintext/ciphertext> "
              << "<key> "
              << "<length of key(Optional. be 128, 192, or 256. Default = 256)> "
              << "<iv(Optional. Default = {0})>\n";
    exit(-1);
  }

  auto start_time_point = std::chrono::steady_clock::now();

  std::ifstream in(in_path, std::ios::binary);
  // input_text
  if (!in.good()) {
    std::cerr << "There are some problems when trying to open the plaintext/ciphertext file\n";
    exit(-1);
  }

  in.seekg(0, std::ios::end);
  auto input_length = in.tellg();
  auto input_text = std::make_unique<Byte[]>(input_length);

  in.seekg(0);
  in.read(reinterpret_cast<char*>(input_text.get()), input_length);
  in.close();

  std::vector<Byte> text(input_text.get(), input_text.get() + input_length);
  input_text.reset();
  // input_text end
  // key
  in.open(key_path, std::ios::binary);
  if (!in.good()) {
    std::cerr << "There are some problems when trying to open the key file.\n";
    exit(-1);
  }

  in.seekg(0, std::ios::end);
  auto key_length = in.tellg();
  auto input_key = std::make_unique<Byte[]>(key_length);

  in.seekg(0);
  in.read(reinterpret_cast<char*>(input_key.get()), key_length);
  in.close();

  std::vector<Byte> key(input_key.get(), input_key.get() + key_length);
  input_key.reset();
  // key end

  // iv
  std::vector<Byte> iv;
  if (iv_path != "") {
    in.open(iv_path, std::ios::binary);
    if (!in.good()) {
      std::cerr << "There are some problems when trying to open the iv file.\n";
      exit(-1);
    }

    in.seekg(0, std::ios::end);
    auto iv_length = in.tellg();
    auto input_iv = std::make_unique<Byte[]>(16);

    in.seekg(0);
    in.read(reinterpret_cast<char*>(input_iv.get()), 16);
    in.close();

    iv = std::vector<Byte>(input_iv.get(), input_iv.get() + 16);
    input_iv.reset();
  } else {
    iv.assign(16, 0);
  }
  // iv end

  std::vector<Byte> result;

  auto aes_start_time_point = std::chrono::steady_clock::now();

  try {
    if ((std::string)argv[1] == "enc") {
      result = iv_path == "" ? aes.Encrypt(text, key, option) : aes.Encrypt(text, key, option, iv);
    } else {
      result = iv_path == "" ? aes.Decrypt(text, key, option) : aes.Decrypt(text, key, option, iv);
    }
  } catch (const std::exception& e) {
    std::cerr << e.what() << '\n';
    exit(-1);
  }

  auto aes_elapsed_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::steady_clock::now() - aes_start_time_point)
                              .count();

  auto temp = std::make_unique<Byte[]>(result.size());
  size_t n = 0;
  std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
  for (const auto& b : result) {
    temp[n] = b;
    n++;
  }
  out.write(reinterpret_cast<const char*>(temp.get()), static_cast<std::streamsize>(result.size()));
  result.clear();
  out.close();

  std::cout << argv[1] << ": " << std::setw(3) << aes_elapsed_time << " milliseconds\n"
            << "Total: " << std::setw(3)
            << std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now() - start_time_point)
                   .count()
            << " milliseconds\n";
}
