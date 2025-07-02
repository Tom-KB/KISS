#include <KISS.h>
#include <stdlib.h>
#include <iostream>
#include <memory>
#include <assert.h>

// Usage example for the LibSodium backend

int main() {

	if (sodium_init() == -1) {
		return 1;
	}

	unique_ptr<KeyExchangeInterface> keServer = make_unique<KeyExchangeSodium>();
	unique_ptr<KeyExchangeInterface> keClient = make_unique<KeyExchangeSodium>(KE_SIDE::Client);

	keClient->computeSharedSecret(keServer->getPublicKey());
	keServer->computeSharedSecret(keClient->getPublicKey());
	
	// In the CLI, half of the secret from one line is equal to the secret of the line's other half
	printf("Client : %s\n", keClient->getSharedSecret().c_str());
	printf("Server : %s\n", keServer->getSharedSecret().c_str());

	// Comparison
	size_t half = keClient->getSharedSecret().size() / 2;
	const string rxStrClient = keClient->getSharedSecret().substr(0, half);
	const string txStrClient = keClient->getSharedSecret().substr(half, half);
	const string rxStrServer = keServer->getSharedSecret().substr(0, half);
	const string txStrServer = keServer->getSharedSecret().substr(half, half);

	// Assertion about the equivalence of keys
	assert(rxStrClient == txStrServer);
	assert(txStrClient == rxStrServer);

	unique_ptr<SymmetricCipherInterface> symCipherClient = make_unique<SymmetricCipherSodium>(keClient->getSharedSecret());

	unique_ptr<SymmetricCipherInterface> symCipherServer = make_unique<SymmetricCipherSodium>(keServer->getSharedSecret());
		
	string message1 = "Hello world!";
	string cipherString1 = symCipherClient->encrypt(message1);
	printf("Cipher1 : %s\n", cipherString1.c_str());
	string uncipherString1 = symCipherServer->decrypt(cipherString1);
	printf("Uncipher1 : %s\n", uncipherString1.c_str());

	assert(uncipherString1 == message1); // Equivalence of message after decryption

	string message2 = "Hello you !!";
	string cipherString2 = symCipherServer->encrypt(message2);
	printf("Cipher1 : %s\n", cipherString2.c_str());
	string uncipherString2 = symCipherClient->decrypt(cipherString2);
	printf("Uncipher1 : %s\n", uncipherString2.c_str());

	assert(uncipherString2 == message2); // Equivalence of message after decryption

	return 0;
}