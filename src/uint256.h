// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UINT256_H
#define BITCOIN_UINT256_H

#include <assert.h>
#include <cstring>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <vector>

/** Template base class for fixed-sized opaque blobs. */
template<unsigned int BITS>
class base_blob
{
protected:
    enum { WIDTH=BITS/8 };
    uint8_t data[WIDTH];
public:
    base_blob()
    {
        memset(data, 0, sizeof(data));
    }

    explicit base_blob(const std::vector<unsigned char>& vch);

    bool IsNull() const
    {
        for (int i = 0; i < WIDTH; i++)
            if (data[i] != 0)
                return false;
        return true;
    }

    void SetNull()
    {
        memset(data, 0, sizeof(data));
    }

    friend inline base_blob operator&(const base_blob&a, const base_blob&b){
        base_blob r;
        for (int i = 0; i < WIDTH; i++)
            r.data[i] = a.data[i]&b.data[i];
        return r;
    }

    friend inline bool operator==(const base_blob& a, const base_blob& b) { return memcmp(a.data, b.data, sizeof(a.data)) == 0; }
    friend inline bool operator!=(const base_blob& a, const base_blob& b) { return memcmp(a.data, b.data, sizeof(a.data)) != 0; }
    friend inline bool operator==(const base_blob& a, uint64_t b)
    {
        if (a.data[0] != (unsigned int)b)
            return false;
        if (a.data[1] != (unsigned int)(b >> 32))
            return false;
        for (int i = 2; i < base_blob::WIDTH; i++)
            if (a.data[i] != 0)
                return false;
        return true;
    }
    friend inline bool operator!=(const base_blob& a, uint64_t b)
    {
        return (!(a == b));
    }
    friend inline bool operator<(const base_blob& a, const base_blob& b) { return memcmp(a.data, b.data, sizeof(a.data)) < 0; }

    void SetHex(const char* psz);
    void SetHex(const std::string& str);
    std::string GetHex() const;
    std::string ToString() const;

    unsigned char* begin()
    {
        return &data[0];
    }

    unsigned char* end()
    {
        return &data[WIDTH];
    }

    const unsigned char* begin() const
    {
        return &data[0];
    }

    const unsigned char* end() const
    {
        return &data[WIDTH];
    }

    unsigned int size() const
    {
        return sizeof(data);
    }

    unsigned int GetSerializeSize(int nType, int nVersion) const
    {
        return sizeof(data);
    }

    base_blob& operator|=(int b)
    {
        data[0] |= (int)b;
        return *this;
    }

    template<typename Stream>
    void Serialize(Stream& s, int nType, int nVersion) const
    {
        s.write((char*)data, sizeof(data));
    }

    template<typename Stream>
    void Unserialize(Stream& s, int nType, int nVersion)
    {
        s.read((char*)data, sizeof(data));
    }
};

/** 160-bit opaque blob.
 * @note This type is called uint160 for historical reasons only. It is an opaque
 * blob of 160 bits and has no integer operations.
 */
class uint160 : public base_blob<160> {
public:
    uint160() {}
    uint160(const base_blob<160>& b) : base_blob<160>(b) {}
    explicit uint160(const std::vector<unsigned char>& vch) : base_blob<160>(vch) {}
};

/** 256-bit opaque blob.
 * @note This type is called uint256 for historical reasons only. It is an
 * opaque blob of 256 bits and has no integer operations. Use arith_uint256 if
 * those are required.
 */
class uint256 : public base_blob<256> {
public:
    uint256() {}
    uint256(const base_blob<256>& b) : base_blob<256>(b) {}
    explicit uint256(const std::vector<unsigned char>& vch) : base_blob<256>(vch) {}
    explicit uint256(const std::string& str){SetHex(str);}
    /** A cheap hash function that just returns 64 bits from the result, it can be
     * used when the contents are considered uniformly random. It is not appropriate
     * when the value can easily be influenced from outside as e.g. a network adversary could
     * provide values to trigger worst-case behavior.
     * @note The result of this function is not stable between little and big endian.
     */
    uint64_t GetCheapHash() const
    {
        uint64_t result;
        memcpy((void*)&result, (void*)data, 8);
        return result;
    }
    friend inline bool operator==(const uint256& a, uint64_t b)                           { return (base_blob)a == b; }
    friend inline bool operator!=(const uint256& a, uint64_t b)                           { return (base_blob)a != b; }
    uint256& operator&=(const uint256& b)
    {
        for (int i = 0; i < WIDTH; i++)
            data[i] &= b.data[i];
        return *this;
    }

    uint256& operator=(uint64_t b)
    {
        data[0] = (unsigned int)b;
        data[1] = (unsigned int)(b >> 32);
        for (int i = 2; i < WIDTH; i++)
            data[i] = 0;
        return *this;
    }

    uint256& operator=(int b)
    {
        data[0] = ( int)b;
        for (int i = 1; i < WIDTH; i++)
            data[i] = 0;
        return *this;
    }

    uint256& operator<<=(unsigned int shift)
    {
        uint256 a(*this);
        memset(data,0,WIDTH);

        int k = shift / 8;
        shift = shift % 8;
        for (int i = 0; i < WIDTH; i++)
        {
            if (i+k+1 < WIDTH && shift != 0)
                data[i+k+1] |= (a.data[i] >> (8-shift));
            if (i+k < WIDTH)
                data[i+k] |= (a.data[i] << shift);
        }
        return *this;
    }
    uint256& operator>>=(unsigned int shift)
    {
        uint256 a(*this);
        memset(data,0,WIDTH);

        int k = shift / 8;//How bytes to shift
        shift = shift % 8; //How bits to shift in current byte
        for (int i = 0; i < WIDTH; i++)
        {
            if (i-k-1 >= 0 && shift != 0)
                data[i-k-1] |= (a.data[i] << (8-shift));
            if (i-k >= 0)
                data[i-k] |= (a.data[i] >> shift);
        }
        return *this;
    }

    uint256& operator>>(char *rdata){
        memcpy(rdata,data,WIDTH/8);
        return *this;
    }

    friend inline const uint256 operator&(const uint256& a, const uint256& b)      { return (base_blob<256>)a &  (base_blob<256>)b; }
    /** A more secure, salted hash function.
     * @note This hash is not stable between little and big endian.
     */
    uint64_t GetHash(const uint256& salt) const;
};

/* uint256 from const char *.
 * This is a separate function because the constructor uint256(const char*) can result
 * in dangerously catching uint256(0).
 */
inline uint256 uint256S(const char *str)
{
    uint256 rv;
    rv.SetHex(str);
    return rv;
}
/* uint256 from std::string.
 * This is a separate function because the constructor uint256(const std::string &str) can result
 * in dangerously catching uint256(0) via std::string(const char*).
 */
inline uint256 uint256S(const std::string& str)
{
    uint256 rv;
    rv.SetHex(str);
    return rv;
}


/** 160-bit opaque blob.
 * @note This type is called uint160 for historical reasons only. It is an opaque
 * blob of 160 bits and has no integer operations.
 */
class uint512 : public base_blob<512> {
public:
    uint512() {}
    uint512(const base_blob<512>& b) : base_blob<512>(b) {}
    explicit uint512(const std::vector<unsigned char>& vch) : base_blob<512>(vch) {}

    uint256 trim256() const
    {
            uint256 ret;
            memcpy((void*)&ret, (void*)data, 256/8);
            return ret;
    }
};

#endif // BITCOIN_UINT256_H
