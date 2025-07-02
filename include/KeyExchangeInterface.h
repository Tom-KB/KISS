#ifndef _KEYEXCHANGEINTERFACE_H
#define _KEYEXCHANGEINTERFACE_H

using namespace std;

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
    virtual string getPublicKey() = 0;
    
    /**
     * This method compute the shared secret used for the symmetric cipher, based on the peer public key and the client private key.
     * @param const string& peerPK
     */
    virtual void computeSharedSecret(const string& peerPK) = 0;
    
    /**
     * This method return the shared secret used for the symmetric cipher
     */
    virtual const string& getSharedSecret() = 0;

protected:
    // Shared secret obtain via the ECDH.
    string sharedSecret;
};

#endif //_KEYEXCHANGEINTERFACE_H