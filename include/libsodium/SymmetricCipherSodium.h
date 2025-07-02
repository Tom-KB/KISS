#pragma once
#include <SymmetricCipherInterface.h>
#include "ConvertToolsSodium.h"
#include <algorithm>

#define chunkSize 1500 // Arbitrary size for a chunk
#define headerSize crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define abytesSize crypto_secretstream_xchacha20poly1305_ABYTES

class SymmetricCipherSodium : public SymmetricCipherInterface {
public:
    SymmetricCipherSodium();
    ~SymmetricCipherSodium();

    /**
     * @param const string& sharedSecret
     */
    SymmetricCipherSodium(const string& sharedSecret);

    /**
     * This method is used to encrypt a string based on your desired algorithm and with the shared secret.
     * @param const string& message
     */
    string encrypt(const string& message);

    /**
     * This method return a decrypt string based on your desired algorithm and the shared secret.
     * @param const string& cipher
     */
    string decrypt(const string& cipher);

protected:
    unsigned char RXHeader[crypto_secretstream_xchacha20poly1305_HEADERBYTES], 
                  TXHeader[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    unsigned char rx[crypto_kx_SESSIONKEYBYTES], tx[crypto_kx_SESSIONKEYBYTES];
    crypto_secretstream_xchacha20poly1305_state statePull, statePush;
};

