/*
 * Copyright (c) 2023 Code Intelligence GmbH
 *
 */

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <string>

#include "utils.h"
#include <cassert>
std::string EncodeBase64(const std::string &input) {
  BIO *bio, *b64;
  BUF_MEM *bufferPtr;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  BIO_write(bio, input.c_str(), input.length());
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bufferPtr);
  BIO_set_close(bio, BIO_NOCLOSE);
  BIO_free_all(bio);
  std::string ret(bufferPtr->data, bufferPtr->length);

  BUF_MEM_free(bufferPtr);
  return ret;
}
