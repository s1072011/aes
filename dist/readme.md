# Usage

./aes [mode:enc/dec] [mode:ecb/cbc...] \<plaintext/ciphertext> \<key> \<length of key(Optional. Can be 128, 192, or 256. Default = 256)> \<iv(Optional. Default = {0})>

e.g.

  &emsp;./aes enc ecb ./plaintext ./key 256
  
  &emsp;./aes dec ecb ./ciphertext ./key 256
