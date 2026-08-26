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
 * Function to convert back a hex string into a caller provided buffer
 * @param out Buffer of at least length bytes, left untouched if the conversion fails
 * @param str
 * @param length
 * @details Writes straight into the caller's buffer rather than allocating one.
 * Every caller here converts key material, and a returned buffer meant it lived on
 * the heap until someone remembered to delete it - which is both a leak and secret
 * bytes left lying in freed memory.
 */
inline void toUnsignedCharArray(unsigned char* out, const std::string& str, size_t length) {
	size_t out_len = 0;

	if (sodium_hex2bin(out, length, str.c_str(), str.size(), nullptr, &out_len, nullptr) != 0 || out_len != length) {
		sodium_memzero(out, length); // Never leave a half converted key behind
		throw std::runtime_error("Conversion error: invalid hex string or incorrect length");
	}
}
