/*
 * High-performance parallel vanity key generator
 * Searches for regex patterns in base64 representation of Ed25519 public keys
 * 
 * Compile with (MinGW-w64):
 *   g++ -O3 -march=native -mtune=native -std=c++17 -pthread -ffast-math -funroll-loops -flto -o pubkey_vanity_fast.exe pubkey_vanity_fast.cpp
 */

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <random>
#include <regex>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <cstdint>
#include <array>

// ============================================================
// SHA512 Implementation (for Ed25519)
// ============================================================

class SHA512 {
public:
    SHA512() { reset(); }
    
    void reset() {
        m_state[0] = 0x6a09e667f3bcc908ULL;
        m_state[1] = 0xbb67ae8584caa73bULL;
        m_state[2] = 0x3c6ef372fe94f82bULL;
        m_state[3] = 0xa54ff53a5f1d36f1ULL;
        m_state[4] = 0x510e527fade682d1ULL;
        m_state[5] = 0x9b05688c2b3e6c1fULL;
        m_state[6] = 0x1f83d9abfb41bd6bULL;
        m_state[7] = 0x5be0cd19137e2179ULL;
        m_bitlen = 0;
        m_buflen = 0;
    }
    
    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; i++) {
            m_buffer[m_buflen++] = data[i];
            if (m_buflen == 128) {
                transform();
                m_bitlen += 1024;
                m_buflen = 0;
            }
        }
    }
    
    void finalize(uint8_t* hash) {
        size_t i = m_buflen;
        
        m_buffer[i++] = 0x80;
        
        if (m_buflen < 112) {
            while (i < 112) m_buffer[i++] = 0x00;
        } else {
            while (i < 128) m_buffer[i++] = 0x00;
            transform();
            memset(m_buffer, 0, 112);
        }
        
        m_bitlen += m_buflen * 8;
        for (int j = 0; j < 8; j++) m_buffer[112 + j] = 0;
        for (int j = 0; j < 8; j++) {
            m_buffer[127 - j] = (m_bitlen >> (j * 8)) & 0xff;
        }
        transform();
        
        for (i = 0; i < 8; i++) {
            hash[i*8]     = (m_state[i] >> 56) & 0xff;
            hash[i*8 + 1] = (m_state[i] >> 48) & 0xff;
            hash[i*8 + 2] = (m_state[i] >> 40) & 0xff;
            hash[i*8 + 3] = (m_state[i] >> 32) & 0xff;
            hash[i*8 + 4] = (m_state[i] >> 24) & 0xff;
            hash[i*8 + 5] = (m_state[i] >> 16) & 0xff;
            hash[i*8 + 6] = (m_state[i] >> 8) & 0xff;
            hash[i*8 + 7] = m_state[i] & 0xff;
        }
    }
    
    static void hash(const uint8_t* data, size_t len, uint8_t* out) {
        SHA512 ctx;
        ctx.update(data, len);
        ctx.finalize(out);
    }

private:
    uint64_t m_state[8];
    uint8_t m_buffer[128];
    size_t m_buflen;
    uint64_t m_bitlen;
    
    static constexpr uint64_t K[80] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };
    
    static inline uint64_t rotr(uint64_t x, uint64_t n) {
        return (x >> n) | (x << (64 - n));
    }
    
    void transform() {
        uint64_t w[80];
        uint64_t a, b, c, d, e, f, g, h;
        
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint64_t)m_buffer[i*8] << 56) | ((uint64_t)m_buffer[i*8+1] << 48) |
                   ((uint64_t)m_buffer[i*8+2] << 40) | ((uint64_t)m_buffer[i*8+3] << 32) |
                   ((uint64_t)m_buffer[i*8+4] << 24) | ((uint64_t)m_buffer[i*8+5] << 16) |
                   ((uint64_t)m_buffer[i*8+6] << 8) | (uint64_t)m_buffer[i*8+7];
        }
        
        for (int i = 16; i < 80; i++) {
            uint64_t s0 = rotr(w[i-15], 1) ^ rotr(w[i-15], 8) ^ (w[i-15] >> 7);
            uint64_t s1 = rotr(w[i-2], 19) ^ rotr(w[i-2], 61) ^ (w[i-2] >> 6);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        
        a = m_state[0]; b = m_state[1]; c = m_state[2]; d = m_state[3];
        e = m_state[4]; f = m_state[5]; g = m_state[6]; h = m_state[7];
        
        for (int i = 0; i < 80; i++) {
            uint64_t S1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
            uint64_t ch = (e & f) ^ (~e & g);
            uint64_t temp1 = h + S1 + ch + K[i] + w[i];
            uint64_t S0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
            uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint64_t temp2 = S0 + maj;
            
            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }
        
        m_state[0] += a; m_state[1] += b; m_state[2] += c; m_state[3] += d;
        m_state[4] += e; m_state[5] += f; m_state[6] += g; m_state[7] += h;
    }
};

constexpr uint64_t SHA512::K[80];

// ============================================================
// Ed25519 Implementation - Optimized with 64-bit limbs
// ============================================================

namespace Ed25519 {

// Field element: 5 x 51-bit limbs (radix 2^51)
// This representation allows faster multiplication without overflow in 128-bit
struct Fe {
    uint64_t v[5];
    
    Fe() { memset(v, 0, sizeof(v)); }
    Fe(uint64_t x) { v[0] = x; v[1] = v[2] = v[3] = v[4] = 0; }
};

// Reduce to canonical form
inline void fe_reduce(Fe& f) {
    const uint64_t mask51 = (1ULL << 51) - 1;
    
    uint64_t c;
    c = f.v[0] >> 51; f.v[0] &= mask51; f.v[1] += c;
    c = f.v[1] >> 51; f.v[1] &= mask51; f.v[2] += c;
    c = f.v[2] >> 51; f.v[2] &= mask51; f.v[3] += c;
    c = f.v[3] >> 51; f.v[3] &= mask51; f.v[4] += c;
    c = f.v[4] >> 51; f.v[4] &= mask51; f.v[0] += c * 19;
    
    // Second pass for full reduction
    c = f.v[0] >> 51; f.v[0] &= mask51; f.v[1] += c;
    c = f.v[1] >> 51; f.v[1] &= mask51; f.v[2] += c;
    c = f.v[2] >> 51; f.v[2] &= mask51; f.v[3] += c;
    c = f.v[3] >> 51; f.v[3] &= mask51; f.v[4] += c;
    c = f.v[4] >> 51; f.v[4] &= mask51; f.v[0] += c * 19;
}

// Load 32 bytes into field element (little-endian)
inline void fe_frombytes(Fe& f, const uint8_t* s) {
    uint64_t h0 = (uint64_t)s[0] | ((uint64_t)s[1] << 8) | ((uint64_t)s[2] << 16) |
                  ((uint64_t)s[3] << 24) | ((uint64_t)s[4] << 32) | ((uint64_t)s[5] << 40) |
                  ((uint64_t)(s[6] & 0x07) << 48);
    uint64_t h1 = ((uint64_t)s[6] >> 3) | ((uint64_t)s[7] << 5) | ((uint64_t)s[8] << 13) |
                  ((uint64_t)s[9] << 21) | ((uint64_t)s[10] << 29) | ((uint64_t)s[11] << 37) |
                  ((uint64_t)(s[12] & 0x3f) << 45);
    uint64_t h2 = ((uint64_t)s[12] >> 6) | ((uint64_t)s[13] << 2) | ((uint64_t)s[14] << 10) |
                  ((uint64_t)s[15] << 18) | ((uint64_t)s[16] << 26) | ((uint64_t)s[17] << 34) |
                  ((uint64_t)s[18] << 42) | ((uint64_t)(s[19] & 0x01) << 50);
    uint64_t h3 = ((uint64_t)s[19] >> 1) | ((uint64_t)s[20] << 7) | ((uint64_t)s[21] << 15) |
                  ((uint64_t)s[22] << 23) | ((uint64_t)s[23] << 31) | ((uint64_t)s[24] << 39) |
                  ((uint64_t)(s[25] & 0x0f) << 47);
    uint64_t h4 = ((uint64_t)s[25] >> 4) | ((uint64_t)s[26] << 4) | ((uint64_t)s[27] << 12) |
                  ((uint64_t)s[28] << 20) | ((uint64_t)s[29] << 28) | ((uint64_t)s[30] << 36) |
                  ((uint64_t)(s[31] & 0x7f) << 44);
    
    f.v[0] = h0; f.v[1] = h1; f.v[2] = h2; f.v[3] = h3; f.v[4] = h4;
}

// Store field element to 32 bytes
inline void fe_tobytes(uint8_t* s, Fe& f) {
    fe_reduce(f);
    
    // Final reduction
    uint64_t q = (f.v[0] + 19) >> 51;
    q = (f.v[1] + q) >> 51;
    q = (f.v[2] + q) >> 51;
    q = (f.v[3] + q) >> 51;
    q = (f.v[4] + q) >> 51;
    
    f.v[0] += 19 * q;
    
    const uint64_t mask51 = (1ULL << 51) - 1;
    uint64_t c;
    c = f.v[0] >> 51; f.v[0] &= mask51; f.v[1] += c;
    c = f.v[1] >> 51; f.v[1] &= mask51; f.v[2] += c;
    c = f.v[2] >> 51; f.v[2] &= mask51; f.v[3] += c;
    c = f.v[3] >> 51; f.v[3] &= mask51; f.v[4] += c;
    f.v[4] &= mask51;
    
    uint64_t h0 = f.v[0], h1 = f.v[1], h2 = f.v[2], h3 = f.v[3], h4 = f.v[4];
    
    s[0]  = h0; s[1]  = h0 >> 8; s[2]  = h0 >> 16; s[3]  = h0 >> 24;
    s[4]  = h0 >> 32; s[5]  = h0 >> 40; s[6]  = (h0 >> 48) | (h1 << 3);
    s[7]  = h1 >> 5; s[8]  = h1 >> 13; s[9]  = h1 >> 21; s[10] = h1 >> 29;
    s[11] = h1 >> 37; s[12] = (h1 >> 45) | (h2 << 6); s[13] = h2 >> 2;
    s[14] = h2 >> 10; s[15] = h2 >> 18; s[16] = h2 >> 26; s[17] = h2 >> 34;
    s[18] = h2 >> 42; s[19] = (h2 >> 50) | (h3 << 1); s[20] = h3 >> 7;
    s[21] = h3 >> 15; s[22] = h3 >> 23; s[23] = h3 >> 31; s[24] = h3 >> 39;
    s[25] = (h3 >> 47) | (h4 << 4); s[26] = h4 >> 4; s[27] = h4 >> 12;
    s[28] = h4 >> 20; s[29] = h4 >> 28; s[30] = h4 >> 36; s[31] = h4 >> 44;
}

// Addition
inline void fe_add(Fe& r, const Fe& a, const Fe& b) {
    r.v[0] = a.v[0] + b.v[0];
    r.v[1] = a.v[1] + b.v[1];
    r.v[2] = a.v[2] + b.v[2];
    r.v[3] = a.v[3] + b.v[3];
    r.v[4] = a.v[4] + b.v[4];
}

// Subtraction
inline void fe_sub(Fe& r, const Fe& a, const Fe& b) {
    // Add 2*p to ensure positive
    r.v[0] = a.v[0] + 0xfffffffffffda - b.v[0];
    r.v[1] = a.v[1] + 0xffffffffffffe - b.v[1];
    r.v[2] = a.v[2] + 0xffffffffffffe - b.v[2];
    r.v[3] = a.v[3] + 0xffffffffffffe - b.v[3];
    r.v[4] = a.v[4] + 0xffffffffffffe - b.v[4];
    fe_reduce(r);
}

// 128-bit helper
#ifdef __SIZEOF_INT128__
typedef unsigned __int128 uint128_t;
#else
// Fallback for MSVC
struct uint128_t {
    uint64_t lo, hi;
    uint128_t() : lo(0), hi(0) {}
    uint128_t(uint64_t x) : lo(x), hi(0) {}
    uint128_t& operator+=(const uint128_t& other) {
        uint64_t old_lo = lo;
        lo += other.lo;
        hi += other.hi + (lo < old_lo ? 1 : 0);
        return *this;
    }
    uint128_t operator*(uint64_t b) const {
        uint128_t r;
        uint64_t a0 = lo & 0xffffffff, a1 = lo >> 32;
        uint64_t b0 = b & 0xffffffff, b1 = b >> 32;
        uint64_t p0 = a0 * b0, p1 = a0 * b1, p2 = a1 * b0, p3 = a1 * b1;
        uint64_t cy = ((p0 >> 32) + (p1 & 0xffffffff) + (p2 & 0xffffffff)) >> 32;
        r.lo = p0 + (p1 << 32) + (p2 << 32);
        r.hi = p3 + (p1 >> 32) + (p2 >> 32) + cy;
        return r;
    }
    operator uint64_t() const { return lo; }
};
inline uint128_t mul64(uint64_t a, uint64_t b) {
    uint128_t r;
    uint64_t a0 = a & 0xffffffff, a1 = a >> 32;
    uint64_t b0 = b & 0xffffffff, b1 = b >> 32;
    uint64_t p0 = a0 * b0, p1 = a0 * b1, p2 = a1 * b0, p3 = a1 * b1;
    uint64_t mid = (p0 >> 32) + (p1 & 0xffffffff) + (p2 & 0xffffffff);
    r.lo = (p0 & 0xffffffff) | (mid << 32);
    r.hi = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
    return r;
}
#endif

// Multiplication - optimized schoolbook with 128-bit intermediates
inline void fe_mul(Fe& r, const Fe& a, const Fe& b) {
    const uint64_t mask51 = (1ULL << 51) - 1;
    
#ifdef __SIZEOF_INT128__
    uint128_t t0 = (uint128_t)a.v[0] * b.v[0];
    uint128_t t1 = (uint128_t)a.v[0] * b.v[1] + (uint128_t)a.v[1] * b.v[0];
    uint128_t t2 = (uint128_t)a.v[0] * b.v[2] + (uint128_t)a.v[1] * b.v[1] + (uint128_t)a.v[2] * b.v[0];
    uint128_t t3 = (uint128_t)a.v[0] * b.v[3] + (uint128_t)a.v[1] * b.v[2] + (uint128_t)a.v[2] * b.v[1] + (uint128_t)a.v[3] * b.v[0];
    uint128_t t4 = (uint128_t)a.v[0] * b.v[4] + (uint128_t)a.v[1] * b.v[3] + (uint128_t)a.v[2] * b.v[2] + (uint128_t)a.v[3] * b.v[1] + (uint128_t)a.v[4] * b.v[0];
    
    uint128_t t5 = (uint128_t)a.v[1] * b.v[4] + (uint128_t)a.v[2] * b.v[3] + (uint128_t)a.v[3] * b.v[2] + (uint128_t)a.v[4] * b.v[1];
    uint128_t t6 = (uint128_t)a.v[2] * b.v[4] + (uint128_t)a.v[3] * b.v[3] + (uint128_t)a.v[4] * b.v[2];
    uint128_t t7 = (uint128_t)a.v[3] * b.v[4] + (uint128_t)a.v[4] * b.v[3];
    uint128_t t8 = (uint128_t)a.v[4] * b.v[4];
    
    // Reduce: multiply high terms by 19 and add to low terms
    t0 += t5 * 19;
    t1 += t6 * 19;
    t2 += t7 * 19;
    t3 += t8 * 19;
    
    // Carry propagation
    t1 += t0 >> 51; uint64_t r0 = (uint64_t)t0 & mask51;
    t2 += t1 >> 51; uint64_t r1 = (uint64_t)t1 & mask51;
    t3 += t2 >> 51; uint64_t r2 = (uint64_t)t2 & mask51;
    t4 += t3 >> 51; uint64_t r3 = (uint64_t)t3 & mask51;
    uint64_t c = (uint64_t)(t4 >> 51); uint64_t r4 = (uint64_t)t4 & mask51;
    
    r0 += c * 19;
    c = r0 >> 51; r0 &= mask51;
    r1 += c;
#else
    uint128_t t0 = mul64(a.v[0], b.v[0]);
    uint128_t t1 = mul64(a.v[0], b.v[1]); t1 += mul64(a.v[1], b.v[0]);
    uint128_t t2 = mul64(a.v[0], b.v[2]); t2 += mul64(a.v[1], b.v[1]); t2 += mul64(a.v[2], b.v[0]);
    uint128_t t3 = mul64(a.v[0], b.v[3]); t3 += mul64(a.v[1], b.v[2]); t3 += mul64(a.v[2], b.v[1]); t3 += mul64(a.v[3], b.v[0]);
    uint128_t t4 = mul64(a.v[0], b.v[4]); t4 += mul64(a.v[1], b.v[3]); t4 += mul64(a.v[2], b.v[2]); t4 += mul64(a.v[3], b.v[1]); t4 += mul64(a.v[4], b.v[0]);
    
    uint128_t t5 = mul64(a.v[1], b.v[4]); t5 += mul64(a.v[2], b.v[3]); t5 += mul64(a.v[3], b.v[2]); t5 += mul64(a.v[4], b.v[1]);
    uint128_t t6 = mul64(a.v[2], b.v[4]); t6 += mul64(a.v[3], b.v[3]); t6 += mul64(a.v[4], b.v[2]);
    uint128_t t7 = mul64(a.v[3], b.v[4]); t7 += mul64(a.v[4], b.v[3]);
    uint128_t t8 = mul64(a.v[4], b.v[4]);
    
    t0 += mul64(t5.lo, 19); t0 += mul64(t5.hi, 19) * (1ULL << 64);
    t1 += mul64(t6.lo, 19); t1 += mul64(t6.hi, 19) * (1ULL << 64);
    t2 += mul64(t7.lo, 19); t2 += mul64(t7.hi, 19) * (1ULL << 64);
    t3 += mul64(t8.lo, 19); t3 += mul64(t8.hi, 19) * (1ULL << 64);
    
    uint64_t r0 = t0.lo & mask51;
    uint64_t c0 = (t0.lo >> 51) | (t0.hi << 13);
    t1.lo += c0;
    uint64_t r1 = t1.lo & mask51;
    uint64_t c1 = (t1.lo >> 51) | (t1.hi << 13);
    t2.lo += c1;
    uint64_t r2 = t2.lo & mask51;
    uint64_t c2 = (t2.lo >> 51) | (t2.hi << 13);
    t3.lo += c2;
    uint64_t r3 = t3.lo & mask51;
    uint64_t c3 = (t3.lo >> 51) | (t3.hi << 13);
    t4.lo += c3;
    uint64_t r4 = t4.lo & mask51;
    uint64_t c = (t4.lo >> 51) | (t4.hi << 13);
    
    r0 += c * 19;
    c = r0 >> 51; r0 &= mask51;
    r1 += c;
#endif
    
    r.v[0] = r0; r.v[1] = r1; r.v[2] = r2; r.v[3] = r3; r.v[4] = r4;
}

// Squaring - optimized
inline void fe_sq(Fe& r, const Fe& a) {
    fe_mul(r, a, a);  // Can be optimized further but this is simple
}

// Copy
inline void fe_copy(Fe& r, const Fe& a) {
    memcpy(r.v, a.v, sizeof(r.v));
}

// Set to 1
inline void fe_one(Fe& r) {
    r.v[0] = 1; r.v[1] = r.v[2] = r.v[3] = r.v[4] = 0;
}

// Set to 0
inline void fe_zero(Fe& r) {
    r.v[0] = r.v[1] = r.v[2] = r.v[3] = r.v[4] = 0;
}

// Negate
inline void fe_neg(Fe& r, const Fe& a) {
    Fe zero;
    fe_zero(zero);
    fe_sub(r, zero, a);
}

// Power: r = a^(2^n)
inline void fe_sq_n(Fe& r, const Fe& a, int n) {
    fe_copy(r, a);
    for (int i = 0; i < n; i++) {
        fe_sq(r, r);
    }
}

// Inversion using Fermat's little theorem: a^(-1) = a^(p-2)
void fe_invert(Fe& r, const Fe& a) {
    Fe t0, t1, t2, t3;
    
    fe_sq(t0, a);           // t0 = a^2
    fe_sq_n(t1, t0, 2);     // t1 = a^8
    fe_mul(t1, t1, a);      // t1 = a^9
    fe_mul(t0, t0, t1);     // t0 = a^11
    fe_sq(t2, t0);          // t2 = a^22
    fe_mul(t1, t1, t2);     // t1 = a^31 = a^(2^5-1)
    fe_sq_n(t2, t1, 5);     // t2 = a^(2^10-2^5)
    fe_mul(t1, t2, t1);     // t1 = a^(2^10-1)
    fe_sq_n(t2, t1, 10);    // t2 = a^(2^20-2^10)
    fe_mul(t2, t2, t1);     // t2 = a^(2^20-1)
    fe_sq_n(t3, t2, 20);    // t3 = a^(2^40-2^20)
    fe_mul(t2, t3, t2);     // t2 = a^(2^40-1)
    fe_sq_n(t2, t2, 10);    // t2 = a^(2^50-2^10)
    fe_mul(t1, t2, t1);     // t1 = a^(2^50-1)
    fe_sq_n(t2, t1, 50);    // t2 = a^(2^100-2^50)
    fe_mul(t2, t2, t1);     // t2 = a^(2^100-1)
    fe_sq_n(t3, t2, 100);   // t3 = a^(2^200-2^100)
    fe_mul(t2, t3, t2);     // t2 = a^(2^200-1)
    fe_sq_n(t2, t2, 50);    // t2 = a^(2^250-2^50)
    fe_mul(t1, t2, t1);     // t1 = a^(2^250-1)
    fe_sq_n(t1, t1, 5);     // t1 = a^(2^255-2^5)
    fe_mul(r, t1, t0);      // r = a^(2^255-21) = a^(p-2)
}

// Point in extended coordinates (X, Y, Z, T) where x = X/Z, y = Y/Z, xy = T/Z
struct Point {
    Fe X, Y, Z, T;
};

// d = -121665/121666
static const uint8_t D_BYTES[32] = {
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
    0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
    0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52
};

// 2*d
static const uint8_t D2_BYTES[32] = {
    0x59, 0xf1, 0xb2, 0x26, 0x94, 0x9b, 0xd6, 0xeb,
    0x56, 0xb1, 0x83, 0x82, 0x9a, 0x14, 0xe0, 0x00,
    0x30, 0xd1, 0xf3, 0xee, 0xf2, 0x80, 0x8e, 0x19,
    0xe7, 0xfc, 0xdf, 0x56, 0xdc, 0xd9, 0x06, 0x24
};

static Fe D, D2;
static bool constants_initialized = false;

void init_constants() {
    if (!constants_initialized) {
        fe_frombytes(D, D_BYTES);
        fe_frombytes(D2, D2_BYTES);
        constants_initialized = true;
    }
}

// Point doubling
void point_double(Point& r, const Point& p) {
    Fe a, b, c, e, f, g, h;
    
    fe_sq(a, p.X);
    fe_sq(b, p.Y);
    fe_sq(c, p.Z);
    fe_add(c, c, c);
    fe_neg(e, a);
    
    Fe xy;
    fe_add(xy, p.X, p.Y);
    fe_sq(xy, xy);
    fe_sub(xy, xy, a);
    fe_sub(xy, xy, b);
    
    fe_add(g, e, b);
    fe_sub(f, g, c);
    fe_sub(h, e, b);
    
    fe_mul(r.X, xy, f);
    fe_mul(r.Y, g, h);
    fe_mul(r.T, xy, h);
    fe_mul(r.Z, f, g);
}

// Point addition
void point_add(Point& r, const Point& p, const Point& q) {
    Fe a, b, c, d, e, f, g, h;
    
    Fe yMinusX_p, yPlusX_p, yMinusX_q, yPlusX_q;
    fe_sub(yMinusX_p, p.Y, p.X);
    fe_add(yPlusX_p, p.Y, p.X);
    fe_sub(yMinusX_q, q.Y, q.X);
    fe_add(yPlusX_q, q.Y, q.X);
    
    fe_mul(a, yMinusX_p, yMinusX_q);
    fe_mul(b, yPlusX_p, yPlusX_q);
    fe_mul(c, p.T, q.T);
    fe_mul(c, c, D2);
    fe_mul(d, p.Z, q.Z);
    fe_add(d, d, d);
    
    fe_sub(e, b, a);
    fe_sub(f, d, c);
    fe_add(g, d, c);
    fe_add(h, b, a);
    
    fe_mul(r.X, e, f);
    fe_mul(r.Y, g, h);
    fe_mul(r.T, e, h);
    fe_mul(r.Z, f, g);
}

// Set point to neutral element
void point_zero(Point& p) {
    fe_zero(p.X);
    fe_one(p.Y);
    fe_one(p.Z);
    fe_zero(p.T);
}

// Base point - Ed25519 generator
static const uint8_t BASE_POINT_Y[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
};

// Compute X from Y for base point (fixed X coordinate)
void get_base_point(Point& B) {
    init_constants();
    
    // y = 4/5 in the field
    fe_frombytes(B.Y, BASE_POINT_Y);
    fe_one(B.Z);
    
    // x^2 = (y^2 - 1) / (d*y^2 + 1)
    Fe y2, num, den, x2;
    fe_sq(y2, B.Y);
    
    Fe one; fe_one(one);
    fe_sub(num, y2, one);
    fe_mul(den, D, y2);
    fe_add(den, den, one);
    
    Fe den_inv;
    fe_invert(den_inv, den);
    fe_mul(x2, num, den_inv);
    
    // x = sqrt(x2) - use Tonelli-Shanks since p = 5 (mod 8)
    // x = x2^((p+3)/8) and check
    Fe x;
    
    // (p+3)/8 exponentiation
    Fe t0, t1, t2, t3;
    fe_sq(t0, x2);           // t0 = x2^2
    fe_mul(t0, t0, x2);      // t0 = x2^3
    fe_sq(t1, t0);           // t1 = x2^6
    fe_mul(t1, t1, x2);      // t1 = x2^7
    fe_sq_n(t2, t1, 3);      // t2 = x2^56
    fe_mul(t1, t2, t1);      // t1 = x2^63
    fe_sq_n(t2, t1, 6);
    fe_mul(t1, t2, t1);
    fe_sq_n(t2, t1, 12);
    fe_mul(t1, t2, t1);
    fe_sq_n(t2, t1, 25);
    fe_mul(t1, t2, t1);
    fe_sq_n(t2, t1, 25);
    fe_mul(t1, t2, t1);
    fe_sq_n(t2, t1, 50);
    fe_mul(t1, t2, t1);
    fe_sq_n(t2, t1, 125);
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    fe_sq(t1, t1);
    fe_mul(x, t1, x2);
    
    // Verify and potentially negate
    Fe check;
    fe_sq(check, x);
    fe_sub(check, check, x2);
    fe_reduce(check);
    
    // If check != 0, multiply by sqrt(-1)
    // For simplicity, we use the known base point X coordinate directly
    static const uint8_t BASE_POINT_X[32] = {
        0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9,
        0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
        0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0,
        0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21
    };
    fe_frombytes(B.X, BASE_POINT_X);
    fe_mul(B.T, B.X, B.Y);
}

// ============================================================
// Precomputed base point table for fast scalar multiplication
// Uses 4-bit windows: table[i][j] = (j+1) * 16^i * B for j in 0..15
// This gives us 64 windows of 4 bits each
// ============================================================

static Point BASE_TABLE[64][16];  // Precomputed [i][j] = (j+1) * 16^i * B
static bool base_table_initialized = false;

void init_base_table() {
    if (base_table_initialized) return;
    
    Point B;
    get_base_point(B);
    
    // For each 4-bit window position
    Point pow16 = B;  // 16^i * B
    for (int i = 0; i < 64; i++) {
        // BASE_TABLE[i][0] = 1 * 16^i * B = pow16
        memcpy(&BASE_TABLE[i][0], &pow16, sizeof(Point));
        
        // BASE_TABLE[i][j] = (j+1) * 16^i * B
        for (int j = 1; j < 16; j++) {
            point_add(BASE_TABLE[i][j], BASE_TABLE[i][j-1], pow16);
        }
        
        // pow16 = 16 * pow16 (4 doublings)
        for (int k = 0; k < 4; k++) {
            point_double(pow16, pow16);
        }
    }
    
    base_table_initialized = true;
}

// Fast scalar multiplication using precomputed table
// scalar is 256 bits = 64 nibbles
void scalar_mult_base(Point& r, const uint8_t scalar[32]) {
    point_zero(r);
    
    // Process each 4-bit nibble
    for (int i = 0; i < 64; i++) {
        int byte_idx = i / 2;
        int nibble;
        if (i & 1) {
            nibble = (scalar[byte_idx] >> 4) & 0xF;
        } else {
            nibble = scalar[byte_idx] & 0xF;
        }
        
        if (nibble > 0) {
            point_add(r, r, BASE_TABLE[i][nibble - 1]);
        }
    }
}

// Generate keypair with precomputed table
void generate_keypair(uint8_t private_key[32], uint8_t public_key[32]) {
    // Random seed using fast xorshift128+
    thread_local uint64_t s0 = std::random_device{}() | 1;
    thread_local uint64_t s1 = std::random_device{}() | 1;
    
    for (int i = 0; i < 4; i++) {
        // xorshift128+
        uint64_t x = s0;
        uint64_t y = s1;
        s0 = y;
        x ^= x << 23;
        s1 = x ^ y ^ (x >> 17) ^ (y >> 26);
        uint64_t r = s1 + y;
        memcpy(private_key + i * 8, &r, 8);
    }
    
    // Hash to get scalar
    uint8_t h[64];
    SHA512::hash(private_key, 32, h);
    
    // Clamp
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    
    // Scalar mult with precomputed base point table
    Point R;
    scalar_mult_base(R, h);
    
    // Compress point to public key
    Fe recip;
    fe_invert(recip, R.Z);
    
    Fe x, y;
    fe_mul(x, R.X, recip);
    fe_mul(y, R.Y, recip);
    
    fe_tobytes(public_key, y);
    
    // Set high bit based on x parity
    uint8_t x_bytes[32];
    fe_tobytes(x_bytes, x);
    public_key[31] |= (x_bytes[0] & 1) << 7;
}

} // namespace Ed25519

// ============================================================
// Global state
// ============================================================

std::atomic<bool> g_found(false);
std::atomic<uint64_t> g_total_attempts(0);

struct Result {
    uint8_t seed[32];        // 32-byte seed (what we generate randomly)
    uint8_t public_key[32];  // 32-byte public key
    uint8_t private_key[64]; // 64-byte private key = seed || public_key
    std::string pubkey_base64;
};

std::atomic<Result*> g_result(nullptr);

// ============================================================
// Utility functions
// ============================================================

std::string to_hex(const uint8_t* data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        result += hex_chars[(data[i] >> 4) & 0xf];
        result += hex_chars[data[i] & 0xf];
    }
    return result;
}

std::string to_base64(const uint8_t* data, size_t len) {
    static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = data[i] << 16;
        if (i + 1 < len) n |= data[i + 1] << 8;
        if (i + 2 < len) n |= data[i + 2];
        
        result += alphabet[(n >> 18) & 0x3f];
        result += alphabet[(n >> 12) & 0x3f];
        result += (i + 1 < len) ? alphabet[(n >> 6) & 0x3f] : '=';
        result += (i + 2 < len) ? alphabet[n & 0x3f] : '=';
    }
    
    return result;
}

// ============================================================
// Worker function
// ============================================================

void worker(int id, const std::string& pattern) {
    std::regex re(pattern);
    uint8_t seed[32], public_key[32];
    uint64_t local_attempts = 0;
    const int batch_size = 100;  // Report every N attempts
    
    // Constants and base table already initialized in main
    
    while (!g_found.load(std::memory_order_relaxed)) {
        for (int i = 0; i < batch_size && !g_found.load(std::memory_order_relaxed); i++) {
            Ed25519::generate_keypair(seed, public_key);
            
            // Convert public key to base64 and check against pattern
            std::string pubkey_base64 = to_base64(public_key, 32);
            local_attempts++;
            
            if (std::regex_search(pubkey_base64, re)) {
                Result* result = new Result;
                memcpy(result->seed, seed, 32);
                memcpy(result->public_key, public_key, 32);
                // Full 64-byte private key = seed || public_key
                memcpy(result->private_key, seed, 32);
                memcpy(result->private_key + 32, public_key, 32);
                result->pubkey_base64 = pubkey_base64;
                
                Result* expected = nullptr;
                if (g_result.compare_exchange_strong(expected, result)) {
                    g_found.store(true, std::memory_order_release);
                } else {
                    delete result;
                }
                return;
            }
        }
        
        g_total_attempts.fetch_add(batch_size, std::memory_order_relaxed);
    }
    
    g_total_attempts.fetch_add(local_attempts % batch_size, std::memory_order_relaxed);
}

// ============================================================
// Main
// ============================================================

int main(int argc, char* argv[]) {
    std::cout << "\n============================================================\n";
    std::cout << "PARALLEL VANITY PUBLIC KEY GENERATOR (C++ Ed25519)\n";
    std::cout << "Searches for regex patterns in base64 public keys\n";
    std::cout << "============================================================\n";
    
    std::string pattern;
    int num_workers;
    
    int cpu_count = std::thread::hardware_concurrency();
    if (cpu_count == 0) cpu_count = 4;
    
    if (argc >= 2) {
        pattern = argv[1];
    } else {
        std::cout << "Enter regex pattern for base64 public key (e.g., '^ABC'): ";
        std::getline(std::cin, pattern);
        if (pattern.empty()) pattern = "^A";
    }
    
    if (argc >= 3) {
        num_workers = std::stoi(argv[2]);
    } else {
        std::cout << "Enter number of workers (press Enter for " << cpu_count << "): ";
        std::string input;
        std::getline(std::cin, input);
        num_workers = input.empty() ? cpu_count : std::stoi(input);
    }
    
    // Validate regex
    try {
        std::regex re(pattern);
    } catch (const std::regex_error& e) {
        std::cerr << "Invalid regex pattern: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "\nPattern: " << pattern << "\n";
    std::cout << "Workers: " << num_workers << "\n";
    std::cout << "Using proper Ed25519 key generation (optimized 51-bit limbs)\n";
    std::cout << "Initializing precomputed tables..." << std::flush;
    
    Ed25519::init_constants();
    Ed25519::init_base_table();
    
    std::cout << " done.\n";
    std::cout << "Press Ctrl+C to stop\n\n";
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Start workers
    std::vector<std::thread> workers;
    for (int i = 0; i < num_workers; i++) {
        workers.emplace_back(worker, i, pattern);
    }
    
    // Progress display
    while (!g_found.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        auto now = std::chrono::high_resolution_clock::now();
        double elapsed = std::chrono::duration<double>(now - start_time).count();
        uint64_t attempts = g_total_attempts.load();
        
        std::cout << "\rAttempts: " << attempts 
                  << " | Rate: " << (uint64_t)(attempts / elapsed) << " keys/s"
                  << " | Elapsed: " << (int)elapsed << "s     " << std::flush;
    }
    
    // Wait for all workers
    for (auto& t : workers) {
        t.join();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    double total_time = std::chrono::duration<double>(end_time - start_time).count();
    
    Result* result = g_result.load();
    if (result) {
        std::cout << "\n\n============================================================\n";
        std::cout << "MATCH FOUND!\n";
        std::cout << "============================================================\n";
        std::cout << "Public Key (base64):  " << result->pubkey_base64 << "\n";
        std::cout << "Public Key (hex):     " << to_hex(result->public_key, 32) << "\n";
        std::cout << "Seed (hex):           " << to_hex(result->seed, 32) << "\n";
        std::cout << "Private Key (hex):    " << to_hex(result->private_key, 64) << "\n";
        std::cout << "Private Key (base64): " << to_base64(result->private_key, 64) << "\n";
        std::cout << "============================================================\n";
        std::cout << "Total attempts: " << g_total_attempts.load() << "\n";
        std::cout << "Time elapsed: " << std::fixed << std::setprecision(2) << total_time << "s\n";
        std::cout << "Average rate: " << (uint64_t)(g_total_attempts.load() / total_time) << " keys/s\n";
        
        delete result;
    }
    
    return 0;
}
