#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/filters.h"

using namespace std;
using namespace CryptoPP;

void encryptFile(string inputFile, string outputFile, byte* key, size_t keySize, byte* iv, size_t ivSize)  {
  // Open the input file and read its contents
  ifstream input(inputFile, ios::binary);
  string plaintext((istreambuf_iterator<char>(input)), istreambuf_iterator<char>());
  input.close();

  // Encrypt the input data using AES-256-CBC mode
  CBC_Mode<AES>::Encryption encryptor(key, keySize, iv);
  string ciphertext;
  StringSource(plaintext, true,
               new StreamTransformationFilter(encryptor,
                                              new StringSink(ciphertext)));

  // Save the encrypted data to a new file
  ofstream output(outputFile, ios::binary);
  output.write(ciphertext.c_str(), ciphertext.size());
  output.close();

  cout << "Encryption complete. Encrypted file saved to " << outputFile << endl;
}

void decryptFile(string inputFile, string outputFile, byte* key, size_t keySize, byte* iv, size_t ivSize)  {
  // Open the input file and read its contents
  ifstream input(inputFile, ios::binary);
  string ciphertext((istreambuf_iterator<char>(input)), istreambuf_iterator<char>());
  input.close();

  // Decrypt the input data using AES-256-CBC mode
  CBC_Mode<AES>::Decryption decryptor(key, keySize, iv);
  string plaintext;
  StringSource(ciphertext, true,
               new StreamTransformationFilter(decryptor,
                                              new StringSink(plaintext)));

  // Save the decrypted data to a new file
  ofstream output(outputFile, ios::binary);
  output.write(plaintext.c_str(), plaintext.size());
  output.close();

  cout << "Decryption complete. Decrypted file saved to " << outputFile << endl;
}

int main(int argc, char* argv[]) {
  if (argc < 4) {
    cout << "Usage: " << argv[0] << " input_video output_encrypted_video output_decrypted_video" << endl;
    return 1;
  }

  // Set the key and IV for encryption and decryption
  byte key[AES::DEFAULT_KEYLENGTH];
  byte iv[AES::BLOCKSIZE];
  memset(key, 0x00, AES::DEFAULT_KEYLENGTH);
  memset(iv, 0x00, AES::BLOCKSIZE);

  // Encrypt the input video
  string inputFile = argv[1];
  string encryptedFile = argv[2];
  encryptFile(inputFile, encryptedFile, key, sizeof(key), iv, sizeof(iv));

  // Decrypt the encrypted video
  string decryptedFile = argv[3];
  decryptFile(encryptedFile, decryptedFile, key, sizeof(key), iv, sizeof(iv));

  return 0;
}