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

	/*
		Sizes around the chunk boundary. Short messages fit in a single chunk and
		hide the way chunks are cut, so a mistake there only shows up past
		chunkSize - abytesSize bytes : exactly the sizes nothing used to cover.
	*/
	const size_t sizes[] = {
		1,
		chunkSize - abytesSize - 1,
		chunkSize - abytesSize,
		chunkSize - abytesSize + 1,   // first size that needs a correctly cut chunk
		chunkSize - 1,
		chunkSize,
		chunkSize + 1,
		2 * chunkSize,
		2 * chunkSize + 1,
		10 * chunkSize + 123
	};

	for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
		string big(sizes[s], '\0');
		for (size_t i = 0; i < big.size(); i++) big[i] = static_cast<char>('A' + (i % 26));

		string cipher = symCipherClient->encrypt(big);
		string clear = symCipherServer->decrypt(cipher);

		printf("size %6zu -> cipher %6zu -> clear %6zu %s\n",
			big.size(), cipher.size(), clear.size(),
			(clear == big) ? "OK" : "FAILED");

		assert(clear == big); // Round trip has to be exact whatever the size
	}

	printf("All symmetric ciphering tests passed.\n");

	return 0;
}