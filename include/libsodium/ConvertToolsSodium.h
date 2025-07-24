#pragma once

#define SODIUM_STATIC
#include <sodium.h>
#include <stdexcept>
#include <string>

/**
 * Function to convert any unsigned char keys into a string in an hex format
 * @param array
 * @param length
 */
inline std::string toString(unsigned char* array, size_t length) {
	std::string res;

	res.resize(length * 2);
	sodium_bin2hex(&res[0], res.size() + 1, array, length);

	return res;
}

/**
 * Function to convert back a string into an unsigned char array
 * @param str
 * @param length
 */
inline unsigned char* toUnsignedCharArray(const std::string& str, size_t length) {
	unsigned char* arr = new unsigned char[length];
	size_t arr_len = 0;

	if (sodium_hex2bin(arr, length, str.c_str(), str.size(), nullptr, &arr_len, nullptr) != 0 || arr_len != length) {
		delete[] arr;
		throw std::runtime_error("Conversion error: invalid hex string or incorrect length");
	}

	return arr;
}
