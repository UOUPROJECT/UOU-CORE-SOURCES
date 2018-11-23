#ifndef UOUHASH_H
#define UOUHASH_H

#include "../uint256.h"
#include "sph_blake.h"
#include "sph_groestl.h"
#include "sph_keccak.h"
#include <openssl/sha.h>
#include "algo/hefty1.h"

#ifndef QT_NO_DEBUG
#include <string>
#endif

#ifdef GLOBALDEFINED
#define GLOBAL
#else
#define GLOBAL extern
#endif


/* Combine stop 64-bits from each hash into a single hash */
inline uint256 CombineHashes(uint256 hash1, uint512 hash2, uint512 hash3, uint512 hash4)
{
    uint256 mask = uint256("0x8000000000000000000000000000000000000000000000000000000000000000");
    uint256 hash[4] = { hash1, hash2.trim256(), hash3.trim256(), hash4.trim256() };

    /* Transpose first 64 bits of each hash into final */
    uint256 final = uint256("0x00");
    for (unsigned int i = 0; i < 64; i++) {
        for (unsigned int j = 0; j < 4; j++) {
            final <<= 1;
            if ((hash[j] & mask) != 0)
                final |= 1;
        }
        mask >>= 1;
    }

    return final;
}

template<typename T1>
inline uint256 UOUHash2(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint256 hash1;
    HEFTY1((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]),
           (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);

    /* HEFTY1 is new, so take an extra security measure to eliminate
     * the possiblity of collisions:
     *
     *     Hash(x) = SHA256(x + HEFTY1(x))
     *
     * N.B. '+' is concatenation.
     */
    uint256 hash2;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx,
                  (pbegin == pend ? pblank : (unsigned char *)&pbegin[0]),
                  (pend - pbegin) * sizeof(pbegin[0]));
    SHA256_Update(&ctx, (unsigned char *)&hash1, sizeof(hash1));
    SHA256_Final((unsigned char *)&hash2, &ctx);

    /* Additional security: Do not rely on a single cryptographic hash
     * function.  Instead, combine the outputs of 4 of the most secure
     * cryptographic hash functions-- SHA256, KECCAK512, GROESTL512
     * and BLAKE512.
     */

    uint512 hash3;
    sph_keccak512_context keccakCtx;
    sph_keccak512_init(&keccakCtx);
    sph_keccak512(&keccakCtx,(pbegin == pend ? pblank : (unsigned char*)&pbegin[0]),
                  (pend - pbegin) * sizeof(pbegin[0]));
    sph_keccak512(&keccakCtx, (unsigned char *)&hash1, sizeof(hash1));
    sph_keccak512_close(&keccakCtx, (void *)&hash3);

    uint512 hash4;
    sph_groestl512_context groestlCtx;
    sph_groestl512_init(&groestlCtx);
    sph_groestl512(&groestlCtx,(pbegin == pend ? pblank : (unsigned char*)&pbegin[0]),
                   (pend - pbegin) * sizeof(pbegin[0]));
    sph_groestl512(&groestlCtx, (unsigned char *)&hash1, sizeof(hash1));
    sph_groestl512_close(&groestlCtx, (void *)&hash4);

    uint512 hash5;
    sph_blake512_context blakeCtx;
    sph_blake512_init(&blakeCtx);
    sph_blake512(&blakeCtx,(pbegin == pend ? pblank : (unsigned char*)&pbegin[0]),
                  (pend - pbegin) * sizeof(pbegin[0]));
    sph_blake512(&blakeCtx, (unsigned char *)&hash1, sizeof(hash1));
    sph_blake512_close(&blakeCtx, (void *)&hash5);

    uint256 final = CombineHashes(hash2, hash3, hash4, hash5);

    return final;
}

template<typename T1>
inline uint256 UOUHash(const T1 pbegin, const T1 pend)
{
    uint256 ret;
    pipe_hash(pbegin,(char*)&ret,pend-pbegin);
    return ret;
}

/*
template<typename T1, typename T2>
inline uint256 UOUHash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end)
{
    static unsigned char pblank[1];
    uint256 hash1;
    HEFTY1_CTX ctx1;
    HEFTY1_Init(&ctx1);
    HEFTY1_Update(&ctx1, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    HEFTY1_Update(&ctx1, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    HEFTY1_Final((unsigned char*)&hash1, &ctx1);

    uint256 hash2;
    SHA256_CTX ctx2;
    SHA256_Init(&ctx2);
    SHA256_Update(&ctx2, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    SHA256_Update(&ctx2, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    SHA256_Update(&ctx2, (unsigned char*)&hash1, sizeof(hash1));
    SHA256_Final((unsigned char*)&hash2, &ctx2);

    uint512 hash3;
    sph_keccak512_context ctx3;
    sph_keccak512_init(&ctx3);
    sph_keccak512(&ctx3, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    sph_keccak512(&ctx3, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    sph_keccak512(&ctx3, (unsigned char*)&hash1, sizeof(hash1));
    sph_keccak512_close(&ctx3, (void *)&hash3);

    uint512 hash4;
    sph_groestl512_context ctx4;
    sph_groestl512_init(&ctx4);
    sph_groestl512(&ctx4, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    sph_groestl512(&ctx4, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    sph_groestl512(&ctx4, (unsigned char*)&hash1, sizeof(hash1));
    sph_groestl512_close(&ctx4, (void *)&hash4);

    uint512 hash5;
    sph_blake512_context ctx5;
    sph_blake512_init(&ctx5);
    sph_blake512(&ctx5, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    sph_blake512(&ctx5, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    sph_blake512(&ctx5, (unsigned char*)&hash1, sizeof(hash1));
    sph_blake512_close(&ctx5, (void *)&hash5);

    return CombineHashes(hash2, hash3, hash4, hash5);
}

template<typename T1, typename T2, typename T3>
inline uint256 UOUHash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end,
                    const T3 p3begin, const T3 p3end)
{
    static unsigned char pblank[1];
    uint256 hash1;
    HEFTY1_CTX ctx1;
    HEFTY1_Init(&ctx1);
    HEFTY1_Update(&ctx1, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    HEFTY1_Update(&ctx1, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    HEFTY1_Update(&ctx1, (p3begin == p3end ? pblank : (unsigned char*)&p3begin[0]), (p3end - p3begin) * sizeof(p3begin[0]));
    HEFTY1_Final((unsigned char*)&hash1, &ctx1);

    uint256 hash2;
    SHA256_CTX ctx2;
    SHA256_Init(&ctx2);
    SHA256_Update(&ctx2, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    SHA256_Update(&ctx2, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    SHA256_Update(&ctx2, (p3begin == p3end ? pblank : (unsigned char*)&p3begin[0]), (p3end - p3begin) * sizeof(p3begin[0]));
    SHA256_Update(&ctx2, (unsigned char*)&hash1, sizeof(hash1));
    SHA256_Final((unsigned char*)&hash2, &ctx2);

    uint512 hash3;
    sph_keccak512_context ctx3;
    sph_keccak512_init(&ctx3);
    sph_keccak512(&ctx3, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    sph_keccak512(&ctx3, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    sph_keccak512(&ctx3, (p3begin == p3end ? pblank : (unsigned char*)&p3begin[0]), (p3end - p3begin) * sizeof(p3begin[0]));
    sph_keccak512(&ctx3, (unsigned char*)&hash1, sizeof(hash1));
    sph_keccak512_close(&ctx3, (void *)&hash3);

    uint512 hash4;
    sph_groestl512_context ctx4;
    sph_groestl512_init(&ctx4);
    sph_groestl512(&ctx4, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    sph_groestl512(&ctx4, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    sph_groestl512(&ctx4, (p3begin == p3end ? pblank : (unsigned char*)&p3begin[0]), (p3end - p3begin) * sizeof(p3begin[0]));
    sph_groestl512(&ctx4, (unsigned char*)&hash1, sizeof(hash1));
    sph_groestl512_close(&ctx4, (void *)&hash4);

    uint512 hash5;
    sph_blake512_context ctx5;
    sph_blake512_init(&ctx5);
    sph_blake512(&ctx5, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    sph_blake512(&ctx5, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    sph_blake512(&ctx5, (p3begin == p3end ? pblank : (unsigned char*)&p3begin[0]), (p3end - p3begin) * sizeof(p3begin[0]));
    sph_blake512(&ctx5, (unsigned char*)&hash1, sizeof(hash1));
    sph_blake512_close(&ctx5, (void *)&hash5);

    return CombineHashes(hash2, hash3, hash4, hash5);
}

unsigned int MurmurHash3(unsigned int nHashSeed, const std::vector<unsigned char>& vDataToHash);
*/
#endif // UOUHASH_H
