#include <KISS.h>

using namespace std;

SymmetricCipherSodium::SymmetricCipherSodium() : RXHeader{}, TXHeader{}, rx{}, tx{}, statePull{}, statePush{} {

}

SymmetricCipherSodium::~SymmetricCipherSodium() {

}

SymmetricCipherSodium::SymmetricCipherSodium(const string& sharedSecret) : RXHeader{}, TXHeader{}, rx{}, tx{}, statePull{}, statePush{} {
	// We extract the RX and TX keys
	size_t half = sharedSecret.size() / 2;
	const string rxStr = sharedSecret.substr(0, half);
	const string txStr = sharedSecret.substr(half, half);

	std::memcpy(rx, toUnsignedCharArray(rxStr, crypto_kx_SESSIONKEYBYTES), crypto_kx_SESSIONKEYBYTES);
	std::memcpy(tx, toUnsignedCharArray(txStr, crypto_kx_SESSIONKEYBYTES), crypto_kx_SESSIONKEYBYTES);
}

string SymmetricCipherSodium::encrypt(const string& message) {
	crypto_secretstream_xchacha20poly1305_init_push(&statePush, TXHeader, tx);
	
	// We add the header at the beginning of the message
	string cipherStr(reinterpret_cast<char*>(TXHeader), headerSize);
	
	unsigned char cipher[chunkSize + abytesSize];

	// We get through each chunk of messages to encrypt them
	for (size_t i = 0; i < message.size(); i += chunkSize) {
		size_t len = min(static_cast<size_t>(chunkSize), message.size() - i);
		const unsigned char* msgChunk = reinterpret_cast<const unsigned char*>(message.data() + i);

		crypto_secretstream_xchacha20poly1305_push(&statePush,
			cipher, NULL,
			msgChunk, len,
			NULL, 0,
			0);

		// Append the encrypted result
		cipherStr.append(reinterpret_cast<char*>(cipher), len + abytesSize);
	}

	return cipherStr;
}

string SymmetricCipherSodium::decrypt(const string& cipher) {
	// A cipher text always carries at least the stream header
	if (cipher.size() < headerSize) {
		throw runtime_error("Decryption error: cipher text too short");
	}

	// We get back the header for the decryption
	memcpy(RXHeader, cipher.data(), headerSize);
	crypto_secretstream_xchacha20poly1305_init_pull(&statePull, RXHeader, rx);

	// A chunk decrypts to at most chunkSize bytes of clear text
	unsigned char message[chunkSize];

	string messageStr;

	/*
		encrypt() emits chunks of chunkSize + abytesSize bytes, so that is the
		amount we have to hand to pull() as well. Reading only chunkSize bytes
		cuts the authentication tag in half and makes every message above
		chunkSize - abytesSize bytes fail to decrypt.
	*/
	for (size_t i = headerSize; i < cipher.size(); i += chunkSize + abytesSize) {
		size_t clen = min(static_cast<size_t>(chunkSize) + abytesSize, cipher.size() - i);
		const unsigned char* cipherChunk = reinterpret_cast<const unsigned char*>(cipher.data() + i);

		// A chunk shorter than the tag itself cannot be authenticated
		if (clen < abytesSize) {
			throw runtime_error("Decryption error: truncated chunk");
		}

		// Try to decrypt the ciphering, if even one chunk is invalid, we throw an error
		if (crypto_secretstream_xchacha20poly1305_pull(&statePull,
			message, NULL, NULL,
			cipherChunk, clen,
			NULL, 0) == -1) {
			throw runtime_error("Decryption error: invalid ciphering");
		}

		// Add the decrypted chunk to the message
		messageStr.append(reinterpret_cast<char*>(message), clen - abytesSize);
	}

	return messageStr;
}