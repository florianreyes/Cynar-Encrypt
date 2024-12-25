#pragma once

#include <string>

class Encrypter
{
public:
    explicit Encrypter(const std::string &password);

    std::string encrypt(std::string &inputFile, std::string &outputFile);

    std::string decrypt(std::string &inputFile, std::string &outputFile);

    unsigned char *getKey() { return key; }

private:
    unsigned char key[32];
    std::string salt;
    static const int iterations = 10000;
    static const size_t saltLength = 16;

    std::string encryptFile(std::string &inputFile, std::string &outputFile);
    std::string decryptFile(std::string &inputFile, std::string &outputFile);

    void deriveKey(const std::string &password);
};
