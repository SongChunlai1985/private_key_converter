#include "bip39.h"

bip39::bip39()
{
    int i = 1;
    foreach (QString Mnemonic, bip39en) {
        Mnemonics.insert(Mnemonic, i++);
    }
}

int bip39::wordsCount(QString entropy)
{
    int entropyBits = entropy.length() * 4;
    int checksumBits = ((entropyBits - 128) / 32) + 4;
    int wordsCount = (entropyBits + checksumBits) / 11;
    return wordsCount;
}


size_t len_to_mask(size_t len)
{
    switch (len) {
    case 128:
        return 0xf0;
    case 160:
        return 0xf8;
    case 192:
        return 0xfc;
    case 224:
        return 0xfe;
    case 256:
        return 0xff;
    default:
        return 0;
    }
    return 0;
}

#define   SHA1_BLOCK_LENGTH		64
#define   SHA1_DIGEST_LENGTH		20
#define   SHA1_DIGEST_STRING_LENGTH	(SHA1_DIGEST_LENGTH   * 2 + 1)
#define SHA256_BLOCK_LENGTH		64
#define SHA256_DIGEST_LENGTH		32
#define SHA256_DIGEST_STRING_LENGTH	(SHA256_DIGEST_LENGTH * 2 + 1)
#define SHA512_BLOCK_LENGTH		128
#define SHA512_DIGEST_LENGTH		64
#define SHA512_DIGEST_STRING_LENGTH	(SHA512_DIGEST_LENGTH * 2 + 1)

int hexValue(char hex_digit)
{
    switch (hex_digit) {
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
        return hex_digit - '0';

    case 'A':
    case 'B':
    case 'C':
    case 'D':
    case 'E':
    case 'F':
        return hex_digit - 'A' + 10;

    case 'a':
    case 'b':
    case 'c':
    case 'd':
    case 'e':
    case 'f':
        return hex_digit - 'a' + 10;
    }
    return 0;
}

std::string base16Decode(const std::string& input)
{
    const auto len = input.length();
    if (len & 1) {
        return "";
        //        throw EncodingException{"base16Decode: Invalid length!"};
    }

    std::string output;
    output.reserve(len / 2);
    for (auto it = input.begin(); it != input.end();) {
        int hi = hexValue(*it++);
        int lo = hexValue(*it++);
        output.push_back(hi << 4 | lo);
    }
    return output;
}

typedef uint8_t  sha2_byte;	/* Exactly 1 byte */
typedef uint32_t sha2_word32;	/* Exactly 4 bytes */
typedef uint64_t sha2_word64;	/* Exactly 8 bytes */

namespace trezor {

typedef struct _SHA1_CTX {
    uint32_t state[5];
    uint64_t bitcount;
    uint32_t buffer[SHA1_BLOCK_LENGTH / sizeof(uint32_t)];
} SHA1_CTX;
typedef struct _SHA256_CTX {
    uint32_t state[8];
    uint64_t bitcount;
    uint32_t buffer[SHA256_BLOCK_LENGTH / sizeof(uint32_t)];
} SHA256_CTX;
typedef struct _SHA512_CTX {
    uint64_t state[8];
    uint64_t bitcount[2];
    uint64_t buffer[SHA512_BLOCK_LENGTH / sizeof(uint64_t)];
} SHA512_CTX;

}
/* Initial hash value H for SHA-256: */
const sha2_word32 sha256_initial_hash_value[8] = {
    0x6a09e667UL,
    0xbb67ae85UL,
    0x3c6ef372UL,
    0xa54ff53aUL,
    0x510e527fUL,
    0x9b05688cUL,
    0x1f83d9abUL,
    0x5be0cd19UL
};

#define MEMCPY_BCOPY(d,s,l)	memcpy((d), (s), (l))

void memzero(void *s, size_t n)
{
    memset(s, 0, n);
}

#if BYTE_ORDER == LITTLE_ENDIAN
#define REVERSE32(w,x)	{ \
    uint32_t tmp = (w); \
    tmp = (tmp >> 16) | (tmp << 16); \
    (x) = ((tmp & 0xff00ff00UL) >> 8) | ((tmp & 0x00ff00ffUL) << 8); \
    }
#define REVERSE64(w,x)	{ \
    uint64_t tmp = (w); \
    tmp = (tmp >> 32) | (tmp << 32); \
    tmp = ((tmp & 0xff00ff00ff00ff00ULL) >> 8) | \
    ((tmp & 0x00ff00ff00ff00ffULL) << 8); \
    (x) = ((tmp & 0xffff0000ffff0000ULL) >> 16) | \
    ((tmp & 0x0000ffff0000ffffULL) << 16); \
    }
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

#ifdef SHA2_UNROLL_TRANSFORM

/* Unrolled SHA-256 round macros: */

#define ROUND256_0_TO_15(a,b,c,d,e,f,g,h)	\
    T1 = (h) + Sigma1_256(e) + Ch((e), (f), (g)) + \
    K256[j] + (W256[j] = *data++); \
    (d) += T1; \
    (h) = T1 + Sigma0_256(a) + Maj((a), (b), (c)); \
    j++

#define ROUND256(a,b,c,d,e,f,g,h)	\
    s0 = W256[(j+1)&0x0f]; \
    s0 = sigma0_256(s0); \
    s1 = W256[(j+14)&0x0f]; \
    s1 = sigma1_256(s1); \
    T1 = (h) + Sigma1_256(e) + Ch((e), (f), (g)) + K256[j] + \
    (W256[j&0x0f] += s1 + W256[(j+9)&0x0f] + s0); \
    (d) += T1; \
    (h) = T1 + Sigma0_256(a) + Maj((a), (b), (c)); \
    j++

void sha256_Transform(const sha2_word32* state_in, const sha2_word32* data, sha2_word32* state_out) {
    sha2_word32	a, b, c, d, e, f, g, h, s0, s1;
    sha2_word32	T1;
    sha2_word32 W256[16];
    int		j;

    /* Initialize registers with the prev. intermediate value */
    a = state_in[0];
    b = state_in[1];
    c = state_in[2];
    d = state_in[3];
    e = state_in[4];
    f = state_in[5];
    g = state_in[6];
    h = state_in[7];

    j = 0;
    do {
        /* Rounds 0 to 15 (unrolled): */
        ROUND256_0_TO_15(a,b,c,d,e,f,g,h);
        ROUND256_0_TO_15(h,a,b,c,d,e,f,g);
        ROUND256_0_TO_15(g,h,a,b,c,d,e,f);
        ROUND256_0_TO_15(f,g,h,a,b,c,d,e);
        ROUND256_0_TO_15(e,f,g,h,a,b,c,d);
        ROUND256_0_TO_15(d,e,f,g,h,a,b,c);
        ROUND256_0_TO_15(c,d,e,f,g,h,a,b);
        ROUND256_0_TO_15(b,c,d,e,f,g,h,a);
    } while (j < 16);

    /* Now for the remaining rounds to 64: */
    do {
        ROUND256(a,b,c,d,e,f,g,h);
        ROUND256(h,a,b,c,d,e,f,g);
        ROUND256(g,h,a,b,c,d,e,f);
        ROUND256(f,g,h,a,b,c,d,e);
        ROUND256(e,f,g,h,a,b,c,d);
        ROUND256(d,e,f,g,h,a,b,c);
        ROUND256(c,d,e,f,g,h,a,b);
        ROUND256(b,c,d,e,f,g,h,a);
    } while (j < 64);

    /* Compute the current intermediate hash value */
    state_out[0] = state_in[0] + a;
    state_out[1] = state_in[1] + b;
    state_out[2] = state_in[2] + c;
    state_out[3] = state_in[3] + d;
    state_out[4] = state_in[4] + e;
    state_out[5] = state_in[5] + f;
    state_out[6] = state_in[6] + g;
    state_out[7] = state_in[7] + h;

    /* Clean up */
    a = b = c = d = e = f = g = h = T1 = 0;
}

#else /* SHA2_UNROLL_TRANSFORM */

/* Shift-right (used in SHA-256, SHA-384, and SHA-512): */
#define SHR(b,x) 		((x) >> (b))
/* 32-bit Rotate-right (used in SHA-256): */
#define ROTR32(b,x)	(((x) >> (b)) | ((x) << (32 - (b))))
/* 64-bit Rotate-right (used in SHA-384 and SHA-512): */
#define ROTR64(b,x)	(((x) >> (b)) | ((x) << (64 - (b))))
/* 32-bit Rotate-left (used in SHA-1): */
#define ROTL32(b,x)	(((x) << (b)) | ((x) >> (32 - (b))))

/* Four of six logical functions used in SHA-256: */
#define Sigma0_256(x)	(ROTR32(2,  (x)) ^ ROTR32(13, (x)) ^ ROTR32(22, (x)))
#define Sigma1_256(x)	(ROTR32(6,  (x)) ^ ROTR32(11, (x)) ^ ROTR32(25, (x)))
#define sigma0_256(x)	(ROTR32(7,  (x)) ^ ROTR32(18, (x)) ^ SHR(3 ,   (x)))
#define sigma1_256(x)	(ROTR32(17, (x)) ^ ROTR32(19, (x)) ^ SHR(10,   (x)))

/* Two of six logical functions used in SHA-1, SHA-256, SHA-384, and SHA-512: */
#define Ch(x,y,z)	(((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/* Hash constant words K for SHA-256: */
static const sha2_word32 K256[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

void sha256_Transform(const sha2_word32* state_in, const sha2_word32* data, sha2_word32* state_out) {
    sha2_word32	a, b, c, d, e, f, g, h, s0, s1;
    sha2_word32	T1, T2, W256[16];
    int		j;

    /* Initialize registers with the prev. intermediate value */
    a = state_in[0];
    b = state_in[1];
    c = state_in[2];
    d = state_in[3];
    e = state_in[4];
    f = state_in[5];
    g = state_in[6];
    h = state_in[7];

    j = 0;
    do {
        /* Apply the SHA-256 compression function to update a..h with copy */
        T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[j] + (W256[j] = *data++);
        T2 = Sigma0_256(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;

        j++;
    } while (j < 16);

    do {
        /* Part of the message block expansion: */
        s0 = W256[(j+1)&0x0f];
        s0 = sigma0_256(s0);
        s1 = W256[(j+14)&0x0f];
        s1 = sigma1_256(s1);

        /* Apply the SHA-256 compression function to update a..h */
        T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[j] +
                (W256[j&0x0f] += s1 + W256[(j+9)&0x0f] + s0);
        T2 = Sigma0_256(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;

        j++;
    } while (j < 64);

    /* Compute the current intermediate hash value */
    state_out[0] = state_in[0] + a;
    state_out[1] = state_in[1] + b;
    state_out[2] = state_in[2] + c;
    state_out[3] = state_in[3] + d;
    state_out[4] = state_in[4] + e;
    state_out[5] = state_in[5] + f;
    state_out[6] = state_in[6] + g;
    state_out[7] = state_in[7] + h;
}

#endif /* SHA2_UNROLL_TRANSFORM */

void sha256_Update(trezor::SHA256_CTX* context, const sha2_byte *data, size_t len) {
    unsigned int	freespace, usedspace;

    if (len == 0) {
        /* Calling with no data is valid - we do nothing */
        return;
    }

    usedspace = (context->bitcount >> 3) % SHA256_BLOCK_LENGTH;
    if (usedspace > 0) {
        /* Calculate how much free space is available in the buffer */
        freespace = SHA256_BLOCK_LENGTH - usedspace;

        if (len >= freespace) {
            /* Fill the buffer completely and process it */
            MEMCPY_BCOPY(((uint8_t*)context->buffer) + usedspace, data, freespace);
            context->bitcount += freespace << 3;
            len -= freespace;
            data += freespace;
#if BYTE_ORDER == LITTLE_ENDIAN
            /* Convert TO host byte order */
            for (int j = 0; j < 16; j++) {
                REVERSE32(context->buffer[j],context->buffer[j]);
            }
#endif
            sha256_Transform(context->state, context->buffer, context->state);
        } else {
            /* The buffer is not yet full */
            MEMCPY_BCOPY(((uint8_t*)context->buffer) + usedspace, data, len);
            context->bitcount += len << 3;
            /* Clean up: */
            usedspace = freespace = 0;
            return;
        }
    }
    while (len >= SHA256_BLOCK_LENGTH) {
        /* Process as many complete blocks as we can */
        MEMCPY_BCOPY(context->buffer, data, SHA256_BLOCK_LENGTH);
#if BYTE_ORDER == LITTLE_ENDIAN
        /* Convert TO host byte order */
        for (int j = 0; j < 16; j++) {
            REVERSE32(context->buffer[j],context->buffer[j]);
        }
#endif
        sha256_Transform(context->state, context->buffer, context->state);
        context->bitcount += SHA256_BLOCK_LENGTH << 3;
        len -= SHA256_BLOCK_LENGTH;
        data += SHA256_BLOCK_LENGTH;
    }
    if (len > 0) {
        /* There's left-overs, so save 'em */
        MEMCPY_BCOPY(context->buffer, data, len);
        context->bitcount += len << 3;
    }
}

/*** SHA-256: *********************************************************/
void sha256_Init(trezor::SHA256_CTX* context) {
    if (context == (trezor::SHA256_CTX*)0) {
        return;
    }
    MEMCPY_BCOPY(context->state, sha256_initial_hash_value, SHA256_DIGEST_LENGTH);
    memzero(context->buffer, SHA256_BLOCK_LENGTH);
    context->bitcount = 0;
}

/*** SHA-256/384/512 Various Length Definitions ***********************/
/* NOTE: Most of these are in sha2.h */
#define   SHA1_SHORT_BLOCK_LENGTH	(SHA1_BLOCK_LENGTH - 8)
#define SHA256_SHORT_BLOCK_LENGTH	(SHA256_BLOCK_LENGTH - 8)
#define SHA512_SHORT_BLOCK_LENGTH	(SHA512_BLOCK_LENGTH - 16)

void sha256_Final(trezor::SHA256_CTX* context, sha2_byte digest[]) {
    unsigned int	usedspace;

    /* If no digest buffer is passed, we don't bother doing this: */
    if (digest != (sha2_byte*)0) {
        usedspace = (context->bitcount >> 3) % SHA256_BLOCK_LENGTH;
        /* Begin padding with a 1 bit: */
        ((uint8_t*)context->buffer)[usedspace++] = 0x80;

        if (usedspace > SHA256_SHORT_BLOCK_LENGTH) {
            memzero(((uint8_t*)context->buffer) + usedspace, SHA256_BLOCK_LENGTH - usedspace);

#if BYTE_ORDER == LITTLE_ENDIAN
            /* Convert TO host byte order */
            for (int j = 0; j < 16; j++) {
                REVERSE32(context->buffer[j],context->buffer[j]);
            }
#endif
            /* Do second-to-last transform: */
            sha256_Transform(context->state, context->buffer, context->state);

            /* And prepare the last transform: */
            usedspace = 0;
        }
        /* Set-up for the last transform: */
        memzero(((uint8_t*)context->buffer) + usedspace, SHA256_SHORT_BLOCK_LENGTH - usedspace);

#if BYTE_ORDER == LITTLE_ENDIAN
        /* Convert TO host byte order */
        for (int j = 0; j < 14; j++) {
            REVERSE32(context->buffer[j],context->buffer[j]);
        }
#endif
        /* Set the bit count: */
        context->buffer[14] = context->bitcount >> 32;
        context->buffer[15] = context->bitcount & 0xffffffff;

        /* Final transform: */
        sha256_Transform(context->state, context->buffer, context->state);

#if BYTE_ORDER == LITTLE_ENDIAN
        /* Convert FROM host byte order */
        for (int j = 0; j < 8; j++) {
            REVERSE32(context->state[j],context->state[j]);
        }
#endif
        MEMCPY_BCOPY(digest, context->state, SHA256_DIGEST_LENGTH);
    }

    /* Clean up state data: */
    memzero(context, sizeof(trezor::SHA256_CTX));
}

void sha256_Raw(const sha2_byte* data, size_t len, uint8_t digest[SHA256_DIGEST_LENGTH]) {
    trezor::SHA256_CTX	context;
    sha256_Init(&context);
    sha256_Update(&context, data, len);
    sha256_Final(&context, digest);
}

std::string bip39::checksum(const std::string& entropy, int m_entropyBits)
{
    std::vector<uint8_t> out;
    out.resize(SHA256_DIGEST_LENGTH);
    auto entrop = base16Decode(entropy);
    sha256_Raw(reinterpret_cast<const uint8_t*>(entrop.c_str()), entrop.size(), &out[0]);

    auto checksumChar = out.at(0);
    auto mask = len_to_mask(m_entropyBits);
    if (mask == 0xf0)
        return std::bitset<4>((checksumChar & mask) >> 4).to_string();
    else if (mask == 0xf8)
        return std::bitset<5>((checksumChar & mask) >> 3).to_string();
    else if (mask == 0xfc)
        return std::bitset<6>((checksumChar & mask) >> 2).to_string();
    else if (mask == 0xfe)
        return std::bitset<7>((checksumChar & mask) >> 1).to_string();
    else if (mask == 0xff)
        return std::bitset<8>((checksumChar & mask)).to_string();
    return "";
}

template <typename Range, typename Value = typename Range::value_type>
std::string Join(Range const& elements, const char* const delimiter)
{
    std::ostringstream os;
    auto b = begin(elements), e = end(elements);

    if (b != e) {
        std::copy(b, prev(e), std::ostream_iterator<Value>(os, delimiter));
        b = prev(e);
    }
    if (b != e) {
        os << *b;
    }

    return os.str();
}

typedef struct _PBKDF2_HMAC_SHA512_CTX {
    uint64_t odig[SHA512_DIGEST_LENGTH / sizeof(uint64_t)];
    uint64_t idig[SHA512_DIGEST_LENGTH / sizeof(uint64_t)];
    uint64_t f[SHA512_DIGEST_LENGTH / sizeof(uint64_t)];
    uint64_t g[SHA512_BLOCK_LENGTH / sizeof(uint64_t)];
    char first;
} PBKDF2_HMAC_SHA512_CTX;

// add way how to mark confidential data
#ifndef CONFIDENTIAL
#define CONFIDENTIAL
#endif

/* Initial hash value H for SHA-512 */
const sha2_word64 sha512_initial_hash_value[8] = {
    0x6a09e667f3bcc908ULL,
    0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL,
    0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL,
    0x5be0cd19137e2179ULL
};

/*** SHA-512: *********************************************************/
void sha512_Init(trezor::SHA512_CTX* context) {
    if (context == (trezor::SHA512_CTX*)0) {
        return;
    }
    MEMCPY_BCOPY(context->state, sha512_initial_hash_value, SHA512_DIGEST_LENGTH);
    memzero(context->buffer, SHA512_BLOCK_LENGTH);
    context->bitcount[0] = context->bitcount[1] =  0;
}

/*
 * Macro for incrementally adding the unsigned 64-bit integer n to the
 * unsigned 128-bit integer (represented using a two-element array of
 * 64-bit words):
 */
#define ADDINC128(w,n)	{ \
    (w)[0] += (sha2_word64)(n); \
    if ((w)[0] < (n)) { \
    (w)[1]++; \
    } \
    }

/* Four of six logical functions used in SHA-384 and SHA-512: */
#define Sigma0_512(x)	(ROTR64(28, (x)) ^ ROTR64(34, (x)) ^ ROTR64(39, (x)))
#define Sigma1_512(x)	(ROTR64(14, (x)) ^ ROTR64(18, (x)) ^ ROTR64(41, (x)))
#define sigma0_512(x)	(ROTR64( 1, (x)) ^ ROTR64( 8, (x)) ^ SHR( 7,   (x)))
#define sigma1_512(x)	(ROTR64(19, (x)) ^ ROTR64(61, (x)) ^ SHR( 6,   (x)))

/* Hash constant words K for SHA-384 and SHA-512: */
static const sha2_word64 K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

void sha512_Transform(const sha2_word64* state_in, const sha2_word64* data, sha2_word64* state_out) {
    sha2_word64	a, b, c, d, e, f, g, h, s0, s1;
    sha2_word64	T1, T2, W512[16];
    int		j;

    /* Initialize registers with the prev. intermediate value */
    a = state_in[0];
    b = state_in[1];
    c = state_in[2];
    d = state_in[3];
    e = state_in[4];
    f = state_in[5];
    g = state_in[6];
    h = state_in[7];

    j = 0;
    do {
        /* Apply the SHA-512 compression function to update a..h with copy */
        T1 = h + Sigma1_512(e) + Ch(e, f, g) + K512[j] + (W512[j] = *data++);
        T2 = Sigma0_512(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;

        j++;
    } while (j < 16);

    do {
        /* Part of the message block expansion: */
        s0 = W512[(j+1)&0x0f];
        s0 = sigma0_512(s0);
        s1 = W512[(j+14)&0x0f];
        s1 =  sigma1_512(s1);

        /* Apply the SHA-512 compression function to update a..h */
        T1 = h + Sigma1_512(e) + Ch(e, f, g) + K512[j] +
                (W512[j&0x0f] += s1 + W512[(j+9)&0x0f] + s0);
        T2 = Sigma0_512(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;

        j++;
    } while (j < 80);

    /* Compute the current intermediate hash value */
    state_out[0] = state_in[0] + a;
    state_out[1] = state_in[1] + b;
    state_out[2] = state_in[2] + c;
    state_out[3] = state_in[3] + d;
    state_out[4] = state_in[4] + e;
    state_out[5] = state_in[5] + f;
    state_out[6] = state_in[6] + g;
    state_out[7] = state_in[7] + h;
}

void sha512_Update(trezor::SHA512_CTX* context, const sha2_byte *data, size_t len) {
    unsigned int	freespace, usedspace;

    if (len == 0) {
        /* Calling with no data is valid - we do nothing */
        return;
    }

    usedspace = (context->bitcount[0] >> 3) % SHA512_BLOCK_LENGTH;
    if (usedspace > 0) {
        /* Calculate how much free space is available in the buffer */
        freespace = SHA512_BLOCK_LENGTH - usedspace;

        if (len >= freespace) {
            /* Fill the buffer completely and process it */
            MEMCPY_BCOPY(((uint8_t*)context->buffer) + usedspace, data, freespace);
            ADDINC128(context->bitcount, freespace << 3);
            len -= freespace;
            data += freespace;
#if BYTE_ORDER == LITTLE_ENDIAN
            /* Convert TO host byte order */
            for (int j = 0; j < 16; j++) {
                REVERSE64(context->buffer[j],context->buffer[j]);
            }
#endif
            sha512_Transform(context->state, context->buffer, context->state);
        } else {
            /* The buffer is not yet full */
            MEMCPY_BCOPY(((uint8_t*)context->buffer) + usedspace, data, len);
            ADDINC128(context->bitcount, len << 3);
            /* Clean up: */
            usedspace = freespace = 0;
            return;
        }
    }
    while (len >= SHA512_BLOCK_LENGTH) {
        /* Process as many complete blocks as we can */
        MEMCPY_BCOPY(context->buffer, data, SHA512_BLOCK_LENGTH);
#if BYTE_ORDER == LITTLE_ENDIAN
        /* Convert TO host byte order */
        for (int j = 0; j < 16; j++) {
            REVERSE64(context->buffer[j],context->buffer[j]);
        }
#endif
        sha512_Transform(context->state, context->buffer, context->state);
        ADDINC128(context->bitcount, SHA512_BLOCK_LENGTH << 3);
        len -= SHA512_BLOCK_LENGTH;
        data += SHA512_BLOCK_LENGTH;
    }
    if (len > 0) {
        /* There's left-overs, so save 'em */
        MEMCPY_BCOPY(context->buffer, data, len);
        ADDINC128(context->bitcount, len << 3);
    }
}

static void sha512_Last(trezor::SHA512_CTX* context) {
    unsigned int	usedspace;

    usedspace = (context->bitcount[0] >> 3) % SHA512_BLOCK_LENGTH;
    /* Begin padding with a 1 bit: */
    ((uint8_t*)context->buffer)[usedspace++] = 0x80;

    if (usedspace > SHA512_SHORT_BLOCK_LENGTH) {
        memzero(((uint8_t*)context->buffer) + usedspace, SHA512_BLOCK_LENGTH - usedspace);

#if BYTE_ORDER == LITTLE_ENDIAN
        /* Convert TO host byte order */
        for (int j = 0; j < 16; j++) {
            REVERSE64(context->buffer[j],context->buffer[j]);
        }
#endif
        /* Do second-to-last transform: */
        sha512_Transform(context->state, context->buffer, context->state);

        /* And prepare the last transform: */
        usedspace = 0;
    }
    /* Set-up for the last transform: */
    memzero(((uint8_t*)context->buffer) + usedspace, SHA512_SHORT_BLOCK_LENGTH - usedspace);

#if BYTE_ORDER == LITTLE_ENDIAN
    /* Convert TO host byte order */
    for (int j = 0; j < 14; j++) {
        REVERSE64(context->buffer[j],context->buffer[j]);
    }
#endif
    /* Store the length of input data (in bits): */
    context->buffer[14] = context->bitcount[1];
    context->buffer[15] = context->bitcount[0];

    /* Final transform: */
    sha512_Transform(context->state, context->buffer, context->state);
}

void sha512_Final(trezor::SHA512_CTX* context, sha2_byte digest[]) {
    /* If no digest buffer is passed, we don't bother doing this: */
    if (digest != (sha2_byte*)0) {
        sha512_Last(context);

        /* Save the hash data for output: */
#if BYTE_ORDER == LITTLE_ENDIAN
        /* Convert FROM host byte order */
        for (int j = 0; j < 8; j++) {
            REVERSE64(context->state[j],context->state[j]);
        }
#endif
        MEMCPY_BCOPY(digest, context->state, SHA512_DIGEST_LENGTH);
    }

    /* Zero out state data */
    memzero(context, sizeof(trezor::SHA512_CTX));
}

void hmac_sha512_prepare(const uint8_t *key, const uint32_t keylen, uint64_t *opad_digest, uint64_t *ipad_digest)
{
    static CONFIDENTIAL uint64_t key_pad[SHA512_BLOCK_LENGTH/sizeof(uint64_t)];

    memzero(key_pad, sizeof(key_pad));
    if (keylen > SHA512_BLOCK_LENGTH) {
        static CONFIDENTIAL trezor::SHA512_CTX context;
        sha512_Init(&context);
        sha512_Update(&context, key, keylen);
        sha512_Final(&context, (uint8_t*)key_pad);
    } else {
        memcpy(key_pad, key, keylen);
    }

    /* compute o_key_pad and its digest */
    for (int i = 0; i < SHA512_BLOCK_LENGTH/(int)sizeof(uint64_t); i++) {
        uint64_t data;
#if BYTE_ORDER == LITTLE_ENDIAN
        REVERSE64(key_pad[i], data);
#else
        data = key_pad[i];
#endif
        key_pad[i] = data ^ 0x5c5c5c5c5c5c5c5c;
    }
    sha512_Transform(sha512_initial_hash_value, key_pad, opad_digest);

    /* convert o_key_pad to i_key_pad and compute its digest */
    for (int i = 0; i < SHA512_BLOCK_LENGTH/(int)sizeof(uint64_t); i++) {
        key_pad[i] = key_pad[i] ^ 0x5c5c5c5c5c5c5c5c ^ 0x3636363636363636;
    }
    sha512_Transform(sha512_initial_hash_value, key_pad, ipad_digest);
    memzero(key_pad, sizeof(key_pad));
}

void pbkdf2_hmac_sha512_Init(PBKDF2_HMAC_SHA512_CTX *pctx, const uint8_t *pass, int passlen, const uint8_t *salt, int saltlen)
{
    trezor::SHA512_CTX ctx;
    uint32_t blocknr = 1;
#if BYTE_ORDER == LITTLE_ENDIAN
    REVERSE32(blocknr, blocknr);
#endif

    hmac_sha512_prepare(pass, passlen, pctx->odig, pctx->idig);
    memset(pctx->g, 0, sizeof(pctx->g));
    pctx->g[8] = 0x8000000000000000;
    pctx->g[15] = (SHA512_BLOCK_LENGTH + SHA512_DIGEST_LENGTH) * 8;

    memcpy (ctx.state, pctx->idig, sizeof(pctx->idig));
    ctx.bitcount[0] = SHA512_BLOCK_LENGTH * 8;
    ctx.bitcount[1] = 0;
    sha512_Update(&ctx, salt, saltlen);
    sha512_Update(&ctx, (uint8_t*)&blocknr, sizeof(blocknr));
    sha512_Final(&ctx, (uint8_t*)pctx->g);
#if BYTE_ORDER == LITTLE_ENDIAN
    for (uint32_t k = 0; k < SHA512_DIGEST_LENGTH / sizeof(uint64_t); k++) {
        REVERSE64(pctx->g[k], pctx->g[k]);
    }
#endif
    sha512_Transform(pctx->odig, pctx->g, pctx->g);
    memcpy(pctx->f, pctx->g, SHA512_DIGEST_LENGTH);
    pctx->first = 1;
}

void pbkdf2_hmac_sha512_Update(PBKDF2_HMAC_SHA512_CTX *pctx, uint32_t iterations)
{
    for (uint32_t i = pctx->first; i < iterations; i++) {
        sha512_Transform(pctx->idig, pctx->g, pctx->g);
        sha512_Transform(pctx->odig, pctx->g, pctx->g);
        for (uint32_t j = 0; j < SHA512_DIGEST_LENGTH / sizeof(uint64_t); j++) {
            pctx->f[j] ^= pctx->g[j];
        }
    }
    pctx->first = 0;
}

void pbkdf2_hmac_sha512_Final(PBKDF2_HMAC_SHA512_CTX *pctx, uint8_t *key)
{
#if BYTE_ORDER == LITTLE_ENDIAN
    for (uint32_t k = 0; k < SHA512_DIGEST_LENGTH/sizeof(uint64_t); k++) {
        REVERSE64(pctx->f[k], pctx->f[k]);
    }
#endif
    memcpy(key, pctx->f, SHA512_DIGEST_LENGTH);
    memzero(pctx, sizeof(PBKDF2_HMAC_SHA512_CTX));
}

void pbkdf2_hmac_sha512(const uint8_t *pass, int passlen, const uint8_t *salt, int saltlen, uint32_t iterations, uint8_t *key)
{
    PBKDF2_HMAC_SHA512_CTX pctx;
    pbkdf2_hmac_sha512_Init(&pctx, pass, passlen, salt, saltlen);
    pbkdf2_hmac_sha512_Update(&pctx, iterations);
    pbkdf2_hmac_sha512_Final(&pctx, key);
}

std::string base16Encode(const std::string& input)
{
    static const char hex_digits[] = "0123456789abcdef";

    std::string output;
    output.reserve(input.length() * 2);
    for (unsigned char c : input) {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}

static constexpr int BIP39_SEED_LEN_512 = 64;             //64byte 512bit
QString bip39::generateSeed(QString salt, QStringList words)
{
    QString pass = words.join(" ");
    std::vector<uint8_t> output(BIP39_SEED_LEN_512);

    static constexpr int rounds = 2048;

    pbkdf2_hmac_sha512(
                reinterpret_cast<const uint8_t*>(pass.toStdString().c_str()),
                pass.length(),
                reinterpret_cast<const uint8_t*>(salt.toStdString().c_str()),
                salt.length(),
                rounds,
                &output[0]);
    std::string seedStr{(char*)output.data(), output.size()};
     auto hexStr = base16Encode(seedStr);
    return QString::fromStdString(hexStr);
}

const char* hex_char_to_bin(char c)
{
    // TODO handle default / error
    switch (toupper(c)) {
    case '0':
        return "0000";
    case '1':
        return "0001";
    case '2':
        return "0010";
    case '3':
        return "0011";
    case '4':
        return "0100";
    case '5':
        return "0101";
    case '6':
        return "0110";
    case '7':
        return "0111";
    case '8':
        return "1000";
    case '9':
        return "1001";
    case 'A':
        return "1010";
    case 'B':
        return "1011";
    case 'C':
        return "1100";
    case 'D':
        return "1101";
    case 'E':
        return "1110";
    case 'F':
        return "1111";
    default:
        return "0000";
    }
}

std::string hex2bits(const std::string& hex) noexcept
{
    std::string bits;
    int len = hex.length();
    bits.reserve(len * 4);
    for (int i = 0; i < len; ++i) {
        bits += hex_char_to_bin(hex.at(i));
    }
    return bits;
}

QStringList bip39::Entropy2Mnemonics(QString entropy)
{
    // Actual words count
    int m_wordsCount = wordsCount(entropy);
    // Overall entropy bits (ENT+CS)
    int m_overallBits = m_wordsCount * 11;
    // Checksum Bits are 1 bit per 3 words, starting from 12 words with 4 CS bits
    int m_checksumBits = ((m_wordsCount - 12) / 3) + 4;
    // Entropy Bits (ENT)
    int m_entropyBits = m_overallBits - m_checksumBits;

    std::string  m_entropy = entropy.toStdString();
    std::string m_checksum = checksum(m_entropy, m_entropyBits);
    Binarystr = hex2bits(m_entropy) + m_checksum;

    std::vector<std::bitset<11>> m_rawBinaryChunks;
    for (size_t i = 0; i < Binarystr.length(); i += 11) {
        const std::string& word11 = Binarystr.substr(i, 11);
        m_rawBinaryChunks.emplace_back(word11);
    }

    std::vector<int> wordsIndex;
    QStringList words;
    std::vector<std::bitset<11>> rawBinaryChunks;

    for (const auto& bit : m_rawBinaryChunks) {
        auto index = bit.to_ulong();
        wordsIndex.emplace_back(index);
        words.push_back(bip39en[index]);
        rawBinaryChunks.emplace_back(bit);
        ++m_wordsCount;
    }
    return words;
}
