#include <KISS.h>

using namespace std;

void saveBase64Key(const unsigned char* key, size_t lenKey, const string& filename) {
	string base64((crypto_sign_PUBLICKEYBYTES * 2), '\0');

	sodium_bin2base64(&base64[0], base64.size(),
		key, lenKey,
		sodium_base64_VARIANT_ORIGINAL);

	base64 = string(base64.c_str());

	ofstream out(filename);
	if (!out) {
		throw runtime_error("Error can't open the file : " + filename);
	}

	out << base64 << '\n';
}

void loadBase64Key(unsigned char* key, size_t lenKey, const string& filename) {
	ifstream in(filename);
	if (!in) {
		throw runtime_error("Error: can't open the key file.");
	}

	string base64;
	if (!getline(in, base64)) {
		throw runtime_error("Error: invalid key file (empty or unreadable).");
	}

	size_t lenBinary;
	if (sodium_base642bin(
		key, lenKey,
		base64.c_str(), base64.length(),
		nullptr, &lenBinary, nullptr,
		sodium_base64_VARIANT_ORIGINAL) != 0) {
		throw runtime_error("Error: could not decode the key.");
	}

	if (lenBinary != lenKey) {
		throw runtime_error("Error: the key's size is not valid.");
	}
}

KeyExchangeSodium::KeyExchangeSodium(KE_SIDE side, bool createFiles) : side(side), rx{}, tx{}, peerPublicKey{}, KeyExchangeInterface() {
	crypto_kx_keypair(publicKey, secretKey);
	if (createFiles) {
		saveBase64Key(publicKey, crypto_kx_PUBLICKEYBYTES, "public.key");
		saveBase64Key(secretKey, crypto_kx_SECRETKEYBYTES, "private.key");
	}
}

KeyExchangeSodium::KeyExchangeSodium(const string& publicKeyFile, const string& secretKeyFile, KE_SIDE side) : side(side), rx{}, tx{}, peerPublicKey{}, KeyExchangeInterface() {
	loadBase64Key(publicKey, crypto_kx_PUBLICKEYBYTES, publicKeyFile);
	loadBase64Key(secretKey, crypto_kx_SECRETKEYBYTES, secretKeyFile);
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