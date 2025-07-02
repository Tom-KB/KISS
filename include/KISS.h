#pragma once

#ifndef _KISS_H
#define _KISS_H

#define SODIUM_BACKEND

#include "KeyExchangeInterface.h"
#include "SymmetricCipherInterface.h"

// Backend

#ifdef SODIUM_BACKEND
		// LibSodium
	#include "libsodium/KeyExchangeSodium.h"
	#include "libsodium/SymmetricCipherSodium.h"
#endif

#endif // _KISS_H