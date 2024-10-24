/*
 * Copyright 2012, 2014 Andrew Ayer
 *
 * This file is part of git-crypt.
 *
 * git-crypt is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * git-crypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with git-crypt.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GNU GPL version 3 section 7:
 *
 * If you modify the Program, or any covered work, by linking or
 * combining it with the OpenSSL project's OpenSSL library (or a
 * modified version of that library), containing parts covered by the
 * terms of the OpenSSL or SSLeay licenses, the licensors of the Program
 * grant you additional permission to convey the resulting work.
 * Corresponding Source for a non-source form of such a combination
 * shall include the source code for the parts of OpenSSL used as well
 * as that of the covered work.
 */


#include <openssl/opensslconf.h>

#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif

#include "crypto.hpp"
#include "key.hpp"
#include "util.hpp"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <sstream>
#include <cstring>

void init_crypto () {}

struct Aes_ecb_encryptor::Aes_impl {
    EVP_CIPHER_CTX *ctx;
};

Aes_ecb_encryptor::Aes_ecb_encryptor (const unsigned char* raw_key)
: impl(new Aes_impl)
{
    impl->ctx = EVP_CIPHER_CTX_new();
    if (!impl->ctx) {
        throw Crypto_error("Aes_ecb_encryptor::Aes_ecb_encryptor", "EVP_CIPHER_CTX_new failed");
    }

    if (!EVP_EncryptInit_ex(impl->ctx, EVP_aes_256_ecb(), NULL, raw_key, NULL)) {
        EVP_CIPHER_CTX_free(impl->ctx);
        throw Crypto_error("Aes_ecb_encryptor::Aes_ecb_encryptor", "EVP_EncryptInit_ex failed");
    }

    // Disable padding for single-block encryption
    if (!EVP_CIPHER_CTX_set_padding(impl->ctx, 0)) {
        EVP_CIPHER_CTX_free(impl->ctx);
        throw Crypto_error("Aes_ecb_encryptor::Aes_ecb_encryptor", "EVP_CIPHER_CTX_set_padding failed");
    }
}

Aes_ecb_encryptor::~Aes_ecb_encryptor ()
{
    // Securely erase key material
    EVP_CIPHER_CTX_free(impl->ctx);
}

void Aes_ecb_encryptor::encrypt(const unsigned char* plain, unsigned char* cipher)
{
    int outlen1 = 0, outlen2 = 0;

    // Reset the context for each encryption
    if (!EVP_EncryptInit_ex(impl->ctx, NULL, NULL, NULL, NULL)) {
        throw Crypto_error("Aes_ecb_encryptor::encrypt", "EVP_EncryptInit_ex reset failed");
    }

    if (!EVP_EncryptUpdate(impl->ctx, cipher, &outlen1, plain, AES_BLOCK_SIZE)) {
        throw Crypto_error("Aes_ecb_encryptor::encrypt", "EVP_EncryptUpdate failed");
    }

    if (!EVP_EncryptFinal_ex(impl->ctx, cipher + outlen1, &outlen2)) {
        throw Crypto_error("Aes_ecb_encryptor::encrypt", "EVP_EncryptFinal_ex failed");
    }

    if (outlen1 + outlen2 != AES_BLOCK_SIZE) {
        throw Crypto_error("Aes_ecb_encryptor::encrypt", "Unexpected output length");
    }
}

struct Hmac_sha1_state::Hmac_impl {
    HMAC_CTX *ctx;
};

Hmac_sha1_state::Hmac_sha1_state (const unsigned char* key, size_t key_len)
: impl(new Hmac_impl)
{
    impl->ctx = HMAC_CTX_new();
    if (!impl->ctx) {
        throw Crypto_error("Hmac_sha1_state::Hmac_sha1_state", "HMAC_CTX_new failed");
    }

    if (HMAC_Init_ex(impl->ctx, key, key_len, EVP_sha1(), NULL) != 1) {
        HMAC_CTX_free(impl->ctx);
        throw Crypto_error("Hmac_sha1_state::Hmac_sha1_state", "HMAC_Init_ex failed");
    }
}

Hmac_sha1_state::~Hmac_sha1_state ()
{
    HMAC_CTX_free(impl->ctx);
}

void Hmac_sha1_state::add (const unsigned char* buffer, size_t buffer_len)
{
    if (HMAC_Update(impl->ctx, buffer, buffer_len) != 1) {
        throw Crypto_error("Hmac_sha1_state::add", "HMAC_Update failed");
    }
}

void Hmac_sha1_state::get (unsigned char* digest)
{
    unsigned int len;
    if (HMAC_Final(impl->ctx, digest, &len) != 1) {
        throw Crypto_error("Hmac_sha1_state::get", "HMAC_Final failed");
    }
}

void random_bytes (unsigned char* buffer, size_t len)
{
    if (RAND_bytes(buffer, len) != 1) {
        std::ostringstream message;
        while (unsigned long code = ERR_get_error()) {
            char error_string[120];
            ERR_error_string_n(code, error_string, sizeof(error_string));
            message << "OpenSSL Error: " << error_string << "; ";
        }
        throw Crypto_error("random_bytes", message.str());
    }
}
