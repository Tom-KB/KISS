#ifndef _KEYEXCHANGEINTERFACE_H
#define _KEYEXCHANGEINTERFACE_H

#include <string>

class KeyExchangeInterface {
public: 
    /*
    * Default constructor for the KeyExchangeInterface 
    * In the implementation it should initialize the public and private key.
    */
    KeyExchangeInterface() : sharedSecret("") {};
    ~KeyExchangeInterface() {} ;

    /**
     * This method return the public key used by the ECDH
     */
    virtual std::string getPublicKey() = 0;
    
    /**
     * This method compute the shared secret used for the symmetric cipher, based on the peer public key and the client private key.
     * @param peerPK
     */
    virtual void computeSharedSecret(const std::string& peerPK) = 0;
    
    /**
     * This method return the shared secret used for the symmetric cipher
     */
    virtual const std::string& getSharedSecret() = 0;

protected:
    // Shared secret obtain via the ECDH.
    std::string sharedSecret;
};

#endif //_KEYEXCHANGEINTERFACE_H