// ============================================================================
// Secura - Main Include Header
// ============================================================================
// Include this single header to access all Secura functionality.
// ============================================================================

#ifndef SECURA_CRYPTO_HPP
#define SECURA_CRYPTO_HPP

// Core types and utilities
#include "secura/types.hpp"
#include "secura/version.hpp"

// Symmetric encryption (AES-256-GCM)
#include "secura/key_manager.hpp"
#include "secura/encryptor.hpp"
#include "secura/decryptor.hpp"

// Asymmetric encryption (RSA)
#include "secura/rsa_key_pair.hpp"
#include "secura/rsa_encryptor.hpp"
#include "secura/rsa_decryptor.hpp"

#endif // SECURA_CRYPTO_HPP
