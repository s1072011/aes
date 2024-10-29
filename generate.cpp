#include <ctime>
#include <fstream>
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
  size_t size = atoi(argv[1]);
  if (!size) {
    std::cerr << "ERROR" << std::endl;
  }

  srand(static_cast<unsigned int>(time(nullptr)));
  auto* data = new unsigned char[size];
  for (int i = 0; i < size; i++) {
    data[i] = static_cast<unsigned char>(rand() % 256);
  }

  std::ofstream pt;
  pt.open("./" + std::to_string(size) + "bytes", std::ios::binary);
  pt.write((const char*)data, size);
  pt.close();
  delete[] data;
}
