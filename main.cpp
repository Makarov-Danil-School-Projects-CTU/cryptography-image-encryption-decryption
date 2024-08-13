#ifndef __PROGTEST__

#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

struct crypto_config {
    const char *m_crypto_function;
    std::unique_ptr<uint8_t[]> m_key;
    std::unique_ptr<uint8_t[]> m_IV;
    size_t m_key_len;
    size_t m_IV_len;
};

#endif /* _PROGTEST_ */

// Init the buffer length
const int BUFFERLEN = 1024;

bool readData(ifstream &readFile, uint8_t *buffer, int &len) {
    readFile.read((char *) buffer, len);
    len = (int) readFile.gcount();
    return !readFile.bad();
}

bool writeData(ofstream &outputFile, uint8_t *buffer, int len) {
    outputFile.write((char *) buffer, len);
    return !outputFile.bad();
}

bool
preprocessImage(ifstream &inputFile, ofstream &outputFile, crypto_config &config, bool isEncrypt, EVP_CIPHER_CTX *ctx) {
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(config.m_crypto_function);

    if (!cipher)
        return false;

    //  Checking if we have the correct key for en/decryption
    if (((int) config.m_key_len < EVP_CIPHER_key_length(cipher) || !config.m_key)) {
        if (!isEncrypt)
            return false;

        config.m_key = make_unique<uint8_t[]>(EVP_CIPHER_key_length(cipher));
        if (!RAND_bytes(config.m_key.get(), EVP_CIPHER_key_length(cipher)))
            return false;
        config.m_key_len = EVP_CIPHER_key_length(cipher);
    }

    //  Checking if IV is required and if we have the correct IV for en/decryption
    if (EVP_CIPHER_iv_length(cipher) && ((int)config.m_IV_len < EVP_CIPHER_iv_length(cipher) || !config.m_IV)) {
        if (!isEncrypt)
            return false;

        config.m_IV = make_unique<uint8_t[]>(EVP_CIPHER_iv_length(cipher));
        if (!RAND_bytes(config.m_IV.get(), EVP_CIPHER_iv_length(cipher)))
            return false;
        config.m_IV_len = EVP_CIPHER_iv_length(cipher);
    }

    if (!EVP_CipherInit(ctx, cipher, config.m_key.get(), config.m_IV.get(), isEncrypt ? 1 : 0))
        return false;

    // Init input and output buffers
    int inputBufferLen = BUFFERLEN;
    int outputLen = 0;

    uint8_t inputBuffer[BUFFERLEN];
    uint8_t outputBuffer[BUFFERLEN];

    // Read file until eof
    while (!inputFile.eof()) {
        if (!readData(inputFile, inputBuffer, inputBufferLen) ||
            !EVP_CipherUpdate(ctx, outputBuffer, &outputLen, inputBuffer, inputBufferLen) ||
            !writeData(outputFile, outputBuffer, outputLen))
            return false;
    }

    if (!EVP_CipherFinal_ex(ctx, outputBuffer, &outputLen) ||
        !writeData(outputFile, outputBuffer, outputLen))
        return false;

    return true;
}

bool
endecryptImage(const std::string &in_filename, const std::string &out_filename, crypto_config &config, bool isEncrypt) {
    if (!config.m_crypto_function)
        return false;

    ifstream inputFile(in_filename, ios::binary);
    if (!inputFile.is_open() || !inputFile.good())
        return false;

    ofstream outputFile(out_filename, ios::binary);
    if (!outputFile.is_open() || !outputFile.good()) {
        inputFile.close();
        return false;
    }

//  Check the file size
    if (inputFile.seekg(0, ios::end).tellg() <= 18) {
        inputFile.close();
        outputFile.close();
        return false;
    }

//  Return pointer to beginning of the file
    inputFile.seekg(0, ios::beg);

    int bufferLen = 18;
    uint8_t requiredHeader[18];

//  Trying to read the first 18 bits.
    if (!readData(inputFile, requiredHeader, bufferLen) || bufferLen != 18 ||
        !writeData(outputFile, requiredHeader, bufferLen)) {
        inputFile.close();
        outputFile.close();
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        inputFile.close();
        outputFile.close();
        return false;
    }

    OpenSSL_add_all_ciphers();

    bool res = preprocessImage(inputFile, outputFile, config, isEncrypt, ctx);

    EVP_CIPHER_CTX_free(ctx);
    inputFile.close();
    outputFile.close();

    return res;
}

bool encrypt_data(const std::string &in_filename, const std::string &out_filename, crypto_config &config) {
    return endecryptImage(in_filename, out_filename, config, true);
}

bool decrypt_data(const std::string &in_filename, const std::string &out_filename, crypto_config &config) {
    return endecryptImage(in_filename, out_filename, config, false);
}

#ifndef __PROGTEST__

bool compare_files(const char *name1, const char *name2) {
    ifstream file1(name1, ios::binary);
    ifstream file2(name2, ios::binary);

    if (!file1.is_open() || !file2.is_open())
        return false;

    file1.seekg(0, std::ios::end);
    file2.seekg(0, std::ios::end);

    if (file1.tellg() != file2.tellg())
        return false;

    file1.seekg(0, std::ios::beg);
    file2.seekg(0, std::ios::beg);

    char c1, c2;
    while (file1.get(c1) && file2.get(c2))
        if (c1 != c2)
            return false;

    return !file1.eof() || !file2.eof();
}

int main(void) {
    crypto_config config{nullptr, nullptr, nullptr, 0, 0};

    // ECB mode
    config.m_crypto_function = "AES-128-ECB";
    config.m_key = std::make_unique<uint8_t[]>(16);
    memset(config.m_key.get(), 0, 16);
    config.m_key_len = 16;

    assert(encrypt_data("homer-simpson.TGA", "out_file.TGA", config) &&
           compare_files("out_file.TGA", "homer-simpson_enc_ecb.TGA"));

    assert(decrypt_data("homer-simpson_enc_ecb.TGA", "out_file.TGA", config) &&
           compare_files("out_file.TGA", "homer-simpson.TGA"));

    assert(encrypt_data("UCM8.TGA", "out_file.TGA", config) &&
           compare_files("out_file.TGA", "UCM8_enc_ecb.TGA"));

    assert(decrypt_data("UCM8_enc_ecb.TGA", "out_file.TGA", config) &&
           compare_files("out_file.TGA", "UCM8.TGA"));

    assert(encrypt_data("image_1.TGA", "out_file.TGA", config) &&
           compare_files("out_file.TGA", "ref_1_enc_ecb.TGA"));

    assert(encrypt_data("image_2.TGA", "out_file.TGA", config) &&
           compare_files("out_file.TGA", "ref_2_enc_ecb.TGA"));

    assert(decrypt_data("image_3_enc_ecb.TGA", "out_file.TGA", config) &&
           compare_files("out_file.TGA", "ref_3_dec_ecb.TGA"));

    assert(decrypt_data("image_4_enc_ecb.TGA", "out_file.TGA", config) &&
           compare_files("out_file.TGA", "ref_4_dec_ecb.TGA"));

    // CBC mode
    config.m_crypto_function = "AES-128-CBC";
    config.m_IV = std::make_unique<uint8_t[]>(16);
    config.m_IV_len = 16;
    memset(config.m_IV.get(), 0, 16);

    assert(encrypt_data("UCM8.TGA", "out_file.TGA", config) &&
           compare_files("out_file.TGA", "UCM8_enc_cbc.TGA"));

    assert(decrypt_data("UCM8_enc_cbc.TGA", "out_file.TGA", config) &&
           compare_files("out_file.TGA", "UCM8.TGA"));

    assert(encrypt_data("homer-simpson.TGA", "out_file.TGA", config) &&
           compare_files("out_file.TGA", "homer-simpson_enc_cbc.TGA"));

    assert(decrypt_data("homer-simpson_enc_cbc.TGA", "out_file.TGA", config) &&
           compare_files("out_file.TGA", "homer-simpson.TGA"));

    assert(encrypt_data("image_1.TGA", "out_file.TGA", config) &&
           compare_files("out_file.TGA", "ref_5_enc_cbc.TGA"));

    assert(encrypt_data("image_2.TGA", "out_file.TGA", config) &&
           compare_files("out_file.TGA", "ref_6_enc_cbc.TGA"));

    assert(decrypt_data("image_7_enc_cbc.TGA", "out_file.TGA", config) &&
           compare_files("out_file.TGA", "ref_7_dec_cbc.TGA"));

    assert(decrypt_data("image_8_enc_cbc.TGA", "out_file.TGA", config) &&
           compare_files("out_file.TGA", "ref_8_dec_cbc.TGA"));
    return 0;
}

#endif /* _PROGTEST_ */