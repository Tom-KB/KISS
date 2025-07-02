#include <KISS.h>

KeyExchangeSodium::KeyExchangeSodium(KE_SIDE side) : side(side), rx{}, tx{}, peerPublicKey{}, KeyExchangeInterface() {
	crypto_kx_keypair(publicKey, secretKey);
}

KeyExchangeSodium::~KeyExchangeSodium() {

}

string KeyExchangeSodium::getPublicKey() {
	return toString(publicKey, crypto_kx_PUBLICKEYBYTES);
}

void KeyExchangeSodium::computeSharedSecret(const string& peerPK) {
	unsigned char* temp = toUnsignedCharArray(peerPK, crypto_kx_PUBLICKEYBYTES);
	memcpy_s(peerPublicKey, crypto_kx_PUBLICKEYBYTES, temp, crypto_kx_PUBLICKEYBYTES);
	delete[] temp; 
	// From here the peerPublicKey contain the right information to compute the shared secret

	switch (side) {
		case KE_SIDE::Client:
			crypto_kx_client_session_keys(rx, tx, publicKey, secretKey, peerPublicKey);
			break;
		case KE_SIDE::Server:
			crypto_kx_server_session_keys(rx, tx, publicKey, secretKey, peerPublicKey);
			break;
	}

	string rxString = toString(rx, crypto_kx_SESSIONKEYBYTES);
	string txString = toString(tx, crypto_kx_SESSIONKEYBYTES);
	string rx_txString = rxString + txString;
	sharedSecret = rx_txString;
}

const string& KeyExchangeSodium::getSharedSecret() {
	return sharedSecret;
}