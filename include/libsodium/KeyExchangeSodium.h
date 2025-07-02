#pragma once
#include <KeyExchangeInterface.h>
#include "ConvertToolsSodium.h"

/*
This class is the concrete implementation of the KeyExchangeInterface for libsodium
It can be used multiple time to get multiple shared secrets
*/

enum class KE_SIDE {Client, Server};


class KeyExchangeSodium : public KeyExchangeInterface {
public:
    /*
    * Constructor for the KeyExchangeSodium implementation
    * Initialize the public and private key
    * @param KE_SIDE side
    */
    KeyExchangeSodium(KE_SIDE side = KE_SIDE::Server);
    ~KeyExchangeSodium();

    /**
     * This method return the public key used by the ECDH
     */
    string getPublicKey();

    /**
     * This method compute the shared secret used for the symmetric cipher, based on the peer public key and the client private key.
     * @param const string& peerPK
     */
    void computeSharedSecret(const string& peerPK);

    /**
     * This method return the shared secret used for the symmetric cipher
     */
    const string& getSharedSecret();

protected:
    KE_SIDE side;
    unsigned char publicKey[crypto_kx_PUBLICKEYBYTES];
    unsigned char secretKey[crypto_kx_SECRETKEYBYTES];
    unsigned char peerPublicKey[crypto_kx_PUBLICKEYBYTES];
    unsigned char rx[crypto_kx_SESSIONKEYBYTES], tx[crypto_kx_SESSIONKEYBYTES]; // Receive and Transmit keys
};

