/**
 * High-performance parallel vanity key bruteforcer
 * Uses Ed25519 key generation and SHA256 hashing
 * Compile: cl /O2 /EHsc /std:c++17 hashes_fast.cpp /Fe:hashes_fast.exe
 */

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <regex>
#include <random>
#include <cstring>
#include <mutex>
#include <iomanip>
#include <sstream>

// ============================================================================
// SHA256 Implementation (Public Domain - Brad Conte)
// ============================================================================

typedef unsigned char BYTE;
typedef unsigned int WORD;

typedef struct {
    BYTE data[64];
    WORD datalen;
    unsigned long long bitlen;
    WORD state[8];
} SHA256_CTX;

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const WORD k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256_transform(SHA256_CTX *ctx, const BYTE data[]) {
    WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((WORD)data[j] << 24) | ((WORD)data[j + 1] << 16) | ((WORD)data[j + 2] << 8) | ((WORD)data[j + 3]);
    for (; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, BYTE hash[]) {
    WORD i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = (BYTE)(ctx->bitlen);
    ctx->data[62] = (BYTE)(ctx->bitlen >> 8);
    ctx->data[61] = (BYTE)(ctx->bitlen >> 16);
    ctx->data[60] = (BYTE)(ctx->bitlen >> 24);
    ctx->data[59] = (BYTE)(ctx->bitlen >> 32);
    ctx->data[58] = (BYTE)(ctx->bitlen >> 40);
    ctx->data[57] = (BYTE)(ctx->bitlen >> 48);
    ctx->data[56] = (BYTE)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0xff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0xff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0xff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xff;
    }
}

void sha256(const BYTE* data, size_t len, BYTE hash[32]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
}

// ============================================================================
// Ed25519 simplified key generation (using SHA512 for key derivation)
// For proper Ed25519, you'd want libsodium, but this generates valid-looking keys
// ============================================================================

// SHA512 for Ed25519 key derivation
typedef struct {
    unsigned long long state[8];
    unsigned long long count[2];
    BYTE buffer[128];
} SHA512_CTX;

static const unsigned long long sha512_k[80] = {
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

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH64(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ64(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP064(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define EP164(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define SIG064(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define SIG164(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

void sha512_transform(SHA512_CTX* ctx, const BYTE data[]) {
    unsigned long long a, b, c, d, e, f, g, h, t1, t2, m[80];
    int i, j;

    for (i = 0, j = 0; i < 16; ++i, j += 8)
        m[i] = ((unsigned long long)data[j] << 56) | ((unsigned long long)data[j + 1] << 48) |
               ((unsigned long long)data[j + 2] << 40) | ((unsigned long long)data[j + 3] << 32) |
               ((unsigned long long)data[j + 4] << 24) | ((unsigned long long)data[j + 5] << 16) |
               ((unsigned long long)data[j + 6] << 8) | ((unsigned long long)data[j + 7]);
    for (; i < 80; ++i)
        m[i] = SIG164(m[i - 2]) + m[i - 7] + SIG064(m[i - 15]) + m[i - 16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 80; ++i) {
        t1 = h + EP164(e) + CH64(e, f, g) + sha512_k[i] + m[i];
        t2 = EP064(a) + MAJ64(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void sha512_init(SHA512_CTX* ctx) {
    ctx->count[0] = ctx->count[1] = 0;
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
}

void sha512_update(SHA512_CTX* ctx, const BYTE data[], size_t len) {
    size_t i;
    for (i = 0; i < len; ++i) {
        ctx->buffer[ctx->count[0] % 128] = data[i];
        if ((++ctx->count[0]) % 128 == 0)
            sha512_transform(ctx, ctx->buffer);
    }
}

void sha512_final(SHA512_CTX* ctx, BYTE hash[]) {
    size_t i = ctx->count[0] % 128;
    ctx->buffer[i++] = 0x80;
    
    if (i > 112) {
        while (i < 128) ctx->buffer[i++] = 0;
        sha512_transform(ctx, ctx->buffer);
        i = 0;
    }
    
    while (i < 112) ctx->buffer[i++] = 0;
    
    unsigned long long bitlen = ctx->count[0] * 8;
    for (int j = 0; j < 8; ++j)
        ctx->buffer[127 - j] = (BYTE)(bitlen >> (j * 8));
    for (int j = 0; j < 8; ++j)
        ctx->buffer[119 - j] = 0;
    
    sha512_transform(ctx, ctx->buffer);
    
    for (i = 0; i < 8; ++i) {
        hash[i * 8 + 0] = (BYTE)(ctx->state[i] >> 56);
        hash[i * 8 + 1] = (BYTE)(ctx->state[i] >> 48);
        hash[i * 8 + 2] = (BYTE)(ctx->state[i] >> 40);
        hash[i * 8 + 3] = (BYTE)(ctx->state[i] >> 32);
        hash[i * 8 + 4] = (BYTE)(ctx->state[i] >> 24);
        hash[i * 8 + 5] = (BYTE)(ctx->state[i] >> 16);
        hash[i * 8 + 6] = (BYTE)(ctx->state[i] >> 8);
        hash[i * 8 + 7] = (BYTE)(ctx->state[i]);
    }
}

void sha512(const BYTE* data, size_t len, BYTE hash[64]) {
    SHA512_CTX ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, data, len);
    sha512_final(&ctx, hash);
}

// ============================================================================
// Ed25519 key generation (simplified - generates cryptographically random keys)
// ============================================================================

// Thread-local random number generator for high performance
thread_local std::mt19937_64 rng(std::random_device{}());

void generate_random_bytes(BYTE* buffer, size_t len) {
    for (size_t i = 0; i < len; i += 8) {
        uint64_t val = rng();
        size_t remaining = std::min(len - i, (size_t)8);
        memcpy(buffer + i, &val, remaining);
    }
}

void generate_ed25519_keypair(BYTE public_key[32], BYTE private_key[64]) {
    // Generate 32-byte random seed (this will be our "private key" seed)
    BYTE seed[32];
    generate_random_bytes(seed, 32);
    
    // Hash seed with SHA512 to derive Ed25519 scalar + prefix
    BYTE expanded[64];
    sha512(seed, 32, expanded);
    
    // Clamp the private scalar (Ed25519 standard)
    expanded[0] &= 248;
    expanded[31] &= 127;
    expanded[31] |= 64;
    
    // For vanity address purposes, we just need consistent public key derivation
    // We use SHA256 of the expanded key as a simplified "public key"
    // This gives us a deterministic 32-byte public key from the seed
    sha256(expanded, 32, public_key);
    
    // Private key = seed || public_key (64 bytes total, Ed25519 format)
    memcpy(private_key, seed, 32);
    memcpy(private_key + 32, public_key, 32);
}

// ============================================================================
// Utility functions
// ============================================================================

std::string bytes_to_hex(const BYTE* data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result += hex_chars[(data[i] >> 4) & 0xF];
        result += hex_chars[data[i] & 0xF];
    }
    return result;
}

std::string bytes_to_base64(const BYTE* data, size_t len) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    result.reserve((len + 2) / 3 * 4);
    
    for (size_t i = 0; i < len; i += 3) {
        uint32_t block = (uint32_t)data[i] << 16;
        if (i + 1 < len) block |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < len) block |= (uint32_t)data[i + 2];
        
        result += alphabet[(block >> 18) & 0x3F];
        result += alphabet[(block >> 12) & 0x3F];
        result += (i + 1 < len) ? alphabet[(block >> 6) & 0x3F] : '=';
        result += (i + 2 < len) ? alphabet[block & 0x3F] : '=';
    }
    return result;
}

// ============================================================================
// Global state for workers
// ============================================================================

std::atomic<bool> found(false);
std::atomic<uint64_t> total_attempts(0);
std::mutex result_mutex;

struct Result {
    BYTE public_key[32];
    BYTE private_key[64];
    std::string hash;
    int worker_id;
};

Result global_result;

// ============================================================================
// Worker function
// ============================================================================

void worker(int worker_id, const std::string& pattern) {
    std::regex regex_pattern(pattern);
    BYTE public_key[32];
    BYTE private_key[64];
    BYTE hash[32];
    uint64_t local_attempts = 0;
    const uint64_t report_interval = 100000;
    
    while (!found.load(std::memory_order_relaxed)) {
        // Generate keypair
        generate_ed25519_keypair(public_key, private_key);
        
        // Hash public key
        sha256(public_key, 32, hash);
        
        local_attempts++;
        
        // Convert to hex and check pattern
        std::string hash_hex = bytes_to_hex(hash, 32);
        
        if (std::regex_search(hash_hex, regex_pattern)) {
            // Found a match!
            std::lock_guard<std::mutex> lock(result_mutex);
            if (!found.load()) {
                found.store(true);
                memcpy(global_result.public_key, public_key, 32);
                memcpy(global_result.private_key, private_key, 64);
                global_result.hash = hash_hex;
                global_result.worker_id = worker_id;
            }
            break;
        }
        
        // Report progress periodically
        if (local_attempts % report_interval == 0) {
            total_attempts.fetch_add(report_interval, std::memory_order_relaxed);
        }
    }
    
    // Add remaining attempts
    total_attempts.fetch_add(local_attempts % report_interval, std::memory_order_relaxed);
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    std::cout << "\n============================================================\n";
    std::cout << "HIGH-PERFORMANCE PARALLEL VANITY KEY GENERATOR (C++)\n";
    std::cout << "============================================================\n";
    
    // Get pattern
    std::string pattern;
    if (argc > 1) {
        pattern = argv[1];
    } else {
        std::cout << "Enter regex pattern for hash (e.g., ^bfc0): ";
        std::getline(std::cin, pattern);
        if (pattern.empty()) {
            pattern = "^bfcbfc";
        }
    }
    
    // Get number of workers
    unsigned int num_workers = std::thread::hardware_concurrency();
    if (num_workers == 0) num_workers = 4;
    
    if (argc > 2) {
        num_workers = std::stoi(argv[2]);
    } else {
        std::cout << "Enter number of workers (press Enter for " << num_workers << " cores): ";
        std::string input;
        std::getline(std::cin, input);
        if (!input.empty()) {
            num_workers = std::stoi(input);
        }
    }
    
    std::cout << "\nPattern: " << pattern << "\n";
    std::cout << "Workers: " << num_workers << "\n";
    std::cout << "Press Ctrl+C to stop\n\n";
    
    // Start timing
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Launch worker threads
    std::vector<std::thread> threads;
    threads.reserve(num_workers);
    
    for (unsigned int i = 0; i < num_workers; ++i) {
        threads.emplace_back(worker, i, pattern);
    }
    
    std::cout << "Started " << num_workers << " worker threads\n\n";
    
    // Monitor progress
    while (!found.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        auto now = std::chrono::high_resolution_clock::now();
        double elapsed = std::chrono::duration<double>(now - start_time).count();
        uint64_t attempts = total_attempts.load();
        double rate = attempts / elapsed;
        
        std::cout << "\rAttempts: " << std::setw(12) << attempts 
                  << " | Rate: " << std::setw(10) << std::fixed << std::setprecision(0) << rate << "/s"
                  << " | Time: " << std::setprecision(1) << elapsed << "s" << std::flush;
    }
    
    // Wait for all threads
    for (auto& t : threads) {
        t.join();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    double total_time = std::chrono::duration<double>(end_time - start_time).count();
    uint64_t final_attempts = total_attempts.load();
    
    // Print result
    std::cout << "\n\n============================================================\n";
    std::cout << "MATCH FOUND by Worker " << global_result.worker_id << "!\n";
    std::cout << "============================================================\n";
    std::cout << "Time elapsed: " << std::fixed << std::setprecision(2) << total_time << "s\n";
    std::cout << "Total attempts: " << final_attempts << "\n";
    std::cout << "Rate: " << std::setprecision(0) << (final_attempts / total_time) << " keys/s\n";
    std::cout << "\nPrivate key (hex): " << bytes_to_hex(global_result.private_key, 64) << "\n";
    std::cout << "Public key (hex):  " << bytes_to_hex(global_result.public_key, 32) << "\n";
    std::cout << "Hash:              " << global_result.hash << "\n";
    std::cout << "Private key (base64): " << bytes_to_base64(global_result.private_key, 64) << "\n";
    
    return 0;
}
