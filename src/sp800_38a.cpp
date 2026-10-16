#include "sp800_38a.hpp"
#include <algorithm>

/*
 * NIST SP 800-38A confidentiality modes for AES.
 *
 * These functions operate on raw byte strings and use the AES block primitive
 * from aes.cpp. ECB and CBC optionally use PKCS#7 padding; CFB, OFB, and CTR
 * process partial final segments without padding.
 */

namespace lab {

// Electronic Codebook mode: encrypt each independent block.
Bytes ecb_encrypt(const AES& aes, const Bytes& input, bool padding) {
    const Bytes data = padding ? pad(input) : input;
    check_aligned(data);

    Bytes output;
    for (std::size_t i = 0; i < data.size(); i += 16) {
        append(output, aes.encrypt(block(data, i)));
    }
    return output;
}

// Electronic Codebook mode: decrypt each independent block.
Bytes ecb_decrypt(const AES& aes, const Bytes& input, bool padding) {
    check_aligned(input);

    Bytes output;
    for (std::size_t i = 0; i < input.size(); i += 16) {
        append(output, aes.decrypt(block(input, i)));
    }
    return padding ? unpad(output) : output;
}

// Cipher Block Chaining mode: XOR each plaintext block with the previous
// ciphertext block before applying AES encryption.
Bytes cbc_encrypt(const AES& aes, const Bytes& input, const Bytes& iv, bool padding) {
    check_iv(iv);
    const Bytes data = padding ? pad(input) : input;
    check_aligned(data);

    Bytes output;
    Block previous = block(iv, 0);
    for (std::size_t i = 0; i < data.size(); i += 16) {
        previous = aes.encrypt(xorblock(block(data, i), previous));
        append(output, previous);
    }
    return output;
}

// Cipher Block Chaining mode decryption: decrypt first, then XOR with the
// initialization vector or the preceding ciphertext block.
Bytes cbc_decrypt(const AES& aes, const Bytes& input, const Bytes& iv, bool padding) {
    check_iv(iv);
    check_aligned(input);

    Bytes output;
    Block previous = block(iv, 0);
    for (std::size_t i = 0; i < input.size(); i += 16) {
        const Block current = block(input, i);
        append(output, xorblock(aes.decrypt(current), previous));
        previous = current;
    }
    return padding ? unpad(output) : output;
}

// Shared CFB implementation. Encryption feeds ciphertext back into the
// register; decryption feeds the received ciphertext back into the register.
static Bytes cfb(const AES& aes, const Bytes& input, const Bytes& iv, int bits, bool encrypt) {
    check_iv(iv);
    if (bits < 8 || bits > 128 || bits % 8 != 0) {
        throw std::invalid_argument(
            "CFB segment bits must be 8..128 and byte-aligned");
    }

    const std::size_t segment_size = static_cast<std::size_t>(bits / 8);
    Block register_value = block(iv, 0);
    Bytes output;

    for (std::size_t i = 0; i < input.size(); i += segment_size) {
        const Block stream = aes.encrypt(register_value);
        const std::size_t count =
            std::min(segment_size, input.size() - i);

        for (std::size_t j = 0; j < count; ++j) {
            output.push_back(input[i + j] ^ stream[j]);
        }

        if (count == segment_size) {
            for (std::size_t j = 0; j < 16 - segment_size; ++j) {
                register_value[j] = register_value[j + segment_size];
            }
            for (std::size_t j = 0; j < segment_size; ++j) {
                register_value[16 - segment_size + j] =
                    encrypt ? output[i + j] : input[i + j];
            }
        }
    }
    return output;
}

// CFB encryption with a byte-aligned segment size.
Bytes cfb_encrypt(const AES& aes, const Bytes& input, const Bytes& iv,
                  int bits) {
    return cfb(aes, input, iv, bits, true);
}

// CFB decryption with a byte-aligned segment size.
Bytes cfb_decrypt(const AES& aes, const Bytes& input, const Bytes& iv,
                  int bits) {
    return cfb(aes, input, iv, bits, false);
}

// Output Feedback mode. Encryption and decryption use the same keystream.
Bytes ofb_crypt(const AES& aes, const Bytes& input, const Bytes& iv) {
    check_iv(iv);

    Block feedback = block(iv, 0);
    Bytes output;
    for (std::size_t i = 0; i < input.size(); i += 16) {
        feedback = aes.encrypt(feedback);
        const std::size_t count =
            std::min<std::size_t>(16, input.size() - i);
        for (std::size_t j = 0; j < count; ++j) {
            output.push_back(input[i + j] ^ feedback[j]);
        }
    }
    return output;
}

// Counter mode. The 128-bit counter is incremented in big-endian order after
// each complete block and wraps modulo 2^128.
Bytes ctr_crypt(const AES& aes, const Bytes& input, const Bytes& initial_counter) {
    check_iv(initial_counter);

    Block counter = block(initial_counter, 0);
    Bytes output;
    for (std::size_t i = 0; i < input.size(); i += 16) {
        const Block stream = aes.encrypt(counter);
        const std::size_t count =
            std::min<std::size_t>(16, input.size() - i);
        for (std::size_t j = 0; j < count; ++j) {
            output.push_back(input[i + j] ^ stream[j]);
        }

        if (i + 16 < input.size()) {
            for (int j = 15; j >= 0; --j) {
                if (++counter[static_cast<std::size_t>(j)] != 0) break;
            }
        }
    }
    return output;
}

}
