/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "error/s2n_errno.h"

#include "crypto/s2n_hash.h"

#include "utils/s2n_safety.h"

int s2n_hash_digest_size(s2n_hash_algorithm alg, uint8_t *out)
{
    switch (alg) {
    case S2N_HASH_NONE:     *out = 0;                    break;
    case S2N_HASH_MD5:      *out = MD5_DIGEST_LENGTH;    break;
    case S2N_HASH_SHA1:     *out = SHA_DIGEST_LENGTH;    break;
    case S2N_HASH_SHA224:   *out = SHA224_DIGEST_LENGTH; break;
    case S2N_HASH_SHA256:   *out = SHA256_DIGEST_LENGTH; break;
    case S2N_HASH_SHA384:   *out = SHA384_DIGEST_LENGTH; break;
    case S2N_HASH_SHA512:   *out = SHA512_DIGEST_LENGTH; break;
    case S2N_HASH_MD5_SHA1: *out = MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH; break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }
    return 0;
}

int s2n_hash_init(struct s2n_hash_state *state, s2n_hash_algorithm alg)
{
    int r;
    switch (alg) {
    case S2N_HASH_NONE:
        r = 1;
        break;
    case S2N_HASH_MD5:
        state->hash_ctx.mdctx = EVP_MD_CTX_create();
        r = EVP_DigestInit_ex(state->hash_ctx.mdctx, EVP_md5(), NULL);
        break;
    case S2N_HASH_SHA1:
        state->hash_ctx.mdctx = EVP_MD_CTX_create();
        r = EVP_DigestInit_ex(state->hash_ctx.mdctx, EVP_sha1(), NULL);
        break;
    case S2N_HASH_SHA224:
        state->hash_ctx.mdctx = EVP_MD_CTX_create();
        r = EVP_DigestInit_ex(state->hash_ctx.mdctx, EVP_sha224(), NULL);
        break;
    case S2N_HASH_SHA256:
        state->hash_ctx.mdctx = EVP_MD_CTX_create();
        r = EVP_DigestInit_ex(state->hash_ctx.mdctx, EVP_sha256(), NULL);
        break;
    case S2N_HASH_SHA384:
        state->hash_ctx.mdctx = EVP_MD_CTX_create();
        r = EVP_DigestInit_ex(state->hash_ctx.mdctx, EVP_sha384(), NULL);
        break;
    case S2N_HASH_SHA512:
        state->hash_ctx.mdctx = EVP_MD_CTX_create();
        r = EVP_DigestInit_ex(state->hash_ctx.mdctx, EVP_sha512(), NULL);
        break;
    case S2N_HASH_MD5_SHA1:
        state->hash_ctx.md5_sha1.sha1_ctx = EVP_MD_CTX_create();
        state->hash_ctx.md5_sha1.md5_ctx = EVP_MD_CTX_create();
        r = EVP_DigestInit_ex(state->hash_ctx.md5_sha1.sha1_ctx, EVP_sha1(), NULL);
        r &= EVP_DigestInit_ex(state->hash_ctx.md5_sha1.md5_ctx, EVP_md5(), NULL);
        break;

    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    if (r == 0) {
        S2N_ERROR(S2N_ERR_HASH_INIT_FAILED);
    }

    state->alg = alg;

    return 0;
}

int s2n_hash_update(struct s2n_hash_state *state, const void *data, uint32_t size)
{
    int r;
    switch (state->alg) {
    case S2N_HASH_NONE:
        r = 1;
        break;
    case S2N_HASH_MD5:
        r = EVP_DigestUpdate(state->hash_ctx.mdctx, data, size);
        break;
    case S2N_HASH_SHA1:
        r = EVP_DigestUpdate(state->hash_ctx.mdctx, data, size);
        break;
    case S2N_HASH_SHA224:
        r = EVP_DigestUpdate(state->hash_ctx.mdctx, data, size);
        break;
    case S2N_HASH_SHA256:
        r = EVP_DigestUpdate(state->hash_ctx.mdctx, data, size);
        break;
    case S2N_HASH_SHA384:
        r = EVP_DigestUpdate(state->hash_ctx.mdctx, data, size);
        break;
    case S2N_HASH_SHA512:
        r = EVP_DigestUpdate(state->hash_ctx.mdctx, data, size);
        break;
    case S2N_HASH_MD5_SHA1:
        r = EVP_DigestUpdate(state->hash_ctx.md5_sha1.sha1_ctx, data, size);
        r &= EVP_DigestUpdate(state->hash_ctx.md5_sha1.md5_ctx, data, size);
        break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    if (r == 0) {
        S2N_ERROR(S2N_ERR_HASH_UPDATE_FAILED);
    }

    return 0;
}

int s2n_hash_digest(struct s2n_hash_state *state, void *out, uint32_t size)
{
    int r;
    switch (state->alg) {
    case S2N_HASH_NONE:
        r = 1;
        break;
    case S2N_HASH_MD5:
        eq_check(size, MD5_DIGEST_LENGTH);
        r = EVP_DigestFinal_ex(state->hash_ctx.mdctx, out, (unsigned int *)&size);
        break;
    case S2N_HASH_SHA1:
        eq_check(size, SHA_DIGEST_LENGTH);
        r = EVP_DigestFinal_ex(state->hash_ctx.mdctx, out, (unsigned int *)&size);
        break;
    case S2N_HASH_SHA224:
        eq_check(size, SHA224_DIGEST_LENGTH);
        r = EVP_DigestFinal_ex(state->hash_ctx.mdctx, out, (unsigned int *)&size);
        break;
    case S2N_HASH_SHA256:
        eq_check(size, SHA256_DIGEST_LENGTH);
        r = EVP_DigestFinal_ex(state->hash_ctx.mdctx, out, (unsigned int *)&size);
        break;
    case S2N_HASH_SHA384:
        eq_check(size, SHA384_DIGEST_LENGTH);
        r = EVP_DigestFinal_ex(state->hash_ctx.mdctx, out, (unsigned int *)&size);
        break;
    case S2N_HASH_SHA512:
        eq_check(size, SHA512_DIGEST_LENGTH);
        r = EVP_DigestFinal_ex(state->hash_ctx.mdctx, out, (unsigned int *)&size);
        break;
    case S2N_HASH_MD5_SHA1:
        eq_check(size, MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH);
        r = EVP_DigestFinal_ex(state->hash_ctx.md5_sha1.sha1_ctx, ((uint8_t *) out) + MD5_DIGEST_LENGTH, (unsigned int *)&size);
        r &= EVP_DigestFinal_ex(state->hash_ctx.md5_sha1.md5_ctx, out, (unsigned int *)&size);
        break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    if (r == 0) {
        S2N_ERROR(S2N_ERR_HASH_DIGEST_FAILED);
    }

    return 0;
}

int s2n_hash_reset(struct s2n_hash_state *state)
{
    switch (state->alg) {
    case S2N_HASH_NONE:
    case S2N_HASH_MD5:
    case S2N_HASH_SHA1:
    case S2N_HASH_SHA224:
    case S2N_HASH_SHA256:
    case S2N_HASH_SHA384:
    case S2N_HASH_SHA512:
        EVP_MD_CTX_destroy(state->hash_ctx.mdctx);
        break;
    case S2N_HASH_MD5_SHA1:
        EVP_MD_CTX_destroy(state->hash_ctx.md5_sha1.sha1_ctx);
        EVP_MD_CTX_destroy(state->hash_ctx.md5_sha1.md5_ctx);
        break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    return s2n_hash_init(state, state->alg);
}

int s2n_hash_copy(struct s2n_hash_state *to, struct s2n_hash_state *from)
{
    switch (from->alg) {
    case S2N_HASH_NONE:
    case S2N_HASH_MD5:
    case S2N_HASH_SHA1:
    case S2N_HASH_SHA224:
    case S2N_HASH_SHA256:
    case S2N_HASH_SHA384:
    case S2N_HASH_SHA512:
        to->hash_ctx.mdctx = EVP_MD_CTX_create();
        EVP_MD_CTX_copy(to->hash_ctx.mdctx, from->hash_ctx.mdctx);
        break;
    case S2N_HASH_MD5_SHA1:
        to->hash_ctx.md5_sha1.sha1_ctx = EVP_MD_CTX_create();
        to->hash_ctx.md5_sha1.md5_ctx = EVP_MD_CTX_create();
        EVP_MD_CTX_copy(to->hash_ctx.md5_sha1.sha1_ctx, from->hash_ctx.md5_sha1.sha1_ctx);
        EVP_MD_CTX_copy(to->hash_ctx.md5_sha1.md5_ctx, from->hash_ctx.md5_sha1.md5_ctx);
        break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    to->alg=from->alg;
    
    return 0;
}

