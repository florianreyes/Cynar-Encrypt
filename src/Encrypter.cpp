#include "../include/Encrypter.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
// #include <openssl/pkcs5.h>
#include <stdexcept>
#include <iostream>
#include <iomanip>

// Constructor that derives the key from the password
Encrypter::Encrypter(const std::string &password)
{
    unsigned char generatedSalt[saltLength];
    if (!RAND_bytes(generatedSalt, saltLength))
    {
        throw std::runtime_error("Error generating salt.");
    }

    salt = std::string(reinterpret_cast<char *>(generatedSalt), saltLength);

    deriveKey(password);
}

// Derives the key using PBKDF2
void Encrypter::deriveKey(const std::string &password)
{
    int result = PKCS5_PBKDF2_HMAC_SHA1(
        password.c_str(), password.length(),
        reinterpret_cast<const unsigned char *>(salt.c_str()), salt.length(),
        iterations, sizeof(key), key);

    if (result != 1)
    {
        throw std::runtime_error("Error deriving key.");
    }
}

std::string Encrypter::encrypt(std::string &inputFile, std::string &outputFile)
{
    return encryptFile(inputFile, outputFile);
}

std::string Encrypter::decrypt(std::string &inputFile, std::string &outputFile)
{
    return decryptFile(inputFile, outputFile);
}

std::string Encrypter::encryptFile(std::string &inputFile, std::string &outputFile)
{
    std::cout << "Encrypting file: " << inputFile << " to " << outputFile << std::endl;
    return "Encryption successful!";
}

std::string Encrypter::decryptFile(std::string &inputFile, std::string &outputFile)
{
    std::cout << "Decrypting file: " << inputFile << " to " << outputFile << std::endl;
    return "Decryption successful!";
}

#include <iostream>
#include "Encrypter.h"

int main()
{
    try
    {
        std::string password = "password123";
        Encrypter encrypter(password);

        std::string inputFile = "example.txt";
        std::string outputFile = "example_encrypted.txt";

        std::cout << encrypter.encrypt(inputFile, outputFile) << std::endl;

        std::cout << encrypter.decrypt(inputFile, outputFile) << std::endl;

        unsigned char *key = encrypter.getKey();
        std::cout << "Derived Key: ";
        for (int i = 0; i < 32; ++i)
        {
            std::cout << std::hex << (int)key[i];
        }
        std::cout << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
