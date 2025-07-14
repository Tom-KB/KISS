# KISS 💋

"Keep It Simple, Secure" a small interface for key exchange and symmetric ciphering.
Made for multi-backend.

## Table of Contents

- [Security Considerations](#security-considerations)
- [Features](#features)
- [Usage Example](#usage-example)
- [Architecture](#architecture)
- [Interfaces & Extensibility](#interfaces--extensibility)
- [Contributing](#contributing)

## Security Considerations
Use this library with caution, as overall security depends not only on the backend implementation but also on how you exchange and protect cryptographic keys.

## Features
Here is the list of available backend implementations :  
* LibSodium

## Usage example

You can see usage example in the `main.cpp` for the LibSodium implementation.

## Architecture
Here is a class diagram of the two interfaces of this project : 
![image](https://github.com/user-attachments/assets/8b848bfa-aacd-4623-a6a5-02929c98b79f)

## Interfaces & Extensibility
There is two interfaces `KeyExchangeInterface` and `SymmetricCipherInterface`.  
You can use these in you program and choose one of the implementation.  

### Example with the LibSodium implementation
```cpp
unique_ptr<KeyExchangeInterface> kX = make_unique<KeyExchangeSodium>();
unique_ptr<SymmetricCipherInterface> symCipher = make_unique<SymmetricCipherSodium>(kX->getSharedSecret());
```
This let you the opportunity to change the backend later.

## Contributing
Contributions are welcome.  
Feel free to improve this project by implementing a new backend, updating the existing one, or adding new interfaces if you find them useful.

