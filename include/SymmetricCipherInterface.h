#ifndef _SYMMETRICCIPHERINTERFACE_H
#define _SYMMETRICCIPHERINTERFACE_H

#include <string>

class SymmetricCipherInterface {
public:
    SymmetricCipherInterface() : sharedSecret("") {};
    ~SymmetricCipherInterface() {};

    /**
     * @param sharedSecret
     */
    SymmetricCipherInterface(const std::string& sharedSecret) : sharedSecret(sharedSecret) {};
    
    /**
     * This method is used to encrypt a string based on your desired algorithm and with the shared secret.
     * @param message
     */
    virtual std::string encrypt(const std::string& message) = 0;
    
    /**
     * This method return a decrypt string based on your desired algorithm and the shared secret.
     * @param cipher
     */
    virtual std::string decrypt(const std::string& cipher) = 0;

protected:
    // Shared Secret use as the symmetric key for the cipher.
    const std::string& sharedSecret;
};

#endif //_SYMMETRICCIPHERINTERFACE_H