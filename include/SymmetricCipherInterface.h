#ifndef _SYMMETRICCIPHERINTERFACE_H
#define _SYMMETRICCIPHERINTERFACE_H

using namespace std;

#include <string>

class SymmetricCipherInterface {
public:
    SymmetricCipherInterface() : sharedSecret("") {};
    ~SymmetricCipherInterface() {};

    /**
     * @param const string& sharedSecret
     */
    SymmetricCipherInterface(const string& sharedSecret) : sharedSecret(sharedSecret) {};
    
    /**
     * This method is used to encrypt a string based on your desired algorithm and with the shared secret.
     * @param const string& message
     */
    virtual string encrypt(const string& message) = 0;
    
    /**
     * This method return a decrypt string based on your desired algorithm and the shared secret.
     * @param const string& cipher
     */
    virtual string decrypt(const string& cipher) = 0;

protected:
    // Shared Secret use as the symmetric key for the cipher.
    const const string& sharedSecret;
};

#endif //_SYMMETRICCIPHERINTERFACE_H