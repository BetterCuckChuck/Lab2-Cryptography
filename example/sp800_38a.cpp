#include "sp800_38a.hpp"
#include <algorithm>

/*
 * Example implementation of the NIST SP 800-38A AES confidentiality modes.
 *
 * This file mirrors the library implementation and is kept as a readable
 * reference for ECB, CBC, CFB, OFB, and CTR processing.
 */

namespace lab {

// ECB encrypts each input block independently.
Bytes ecb_encrypt(const AES& aes, const Bytes& input, bool padding) {
    const Bytes data = padding ? pad(input) : input;
    check_aligned(data);
    Bytes output;
    for (std::size_t offset = 0; offset < data.size(); offset += AES::BLOCK_SIZE) {
        append(output, aes.encrypt(block(data, offset)));
    }
    return output;
}

// ECB decrypts each input block independently.
Bytes ecb_decrypt(const AES& aes, const Bytes& input, bool padding) {
    check_aligned(input);
    Bytes output;
    for (std::size_t offset = 0; offset < input.size(); offset += AES::BLOCK_SIZE) {
        append(output, aes.decrypt(block(input, offset)));
    }
    return padding ? unpad(output) : output;
}

// CBC chains each encrypted block into the next block's input.
Bytes cbc_encrypt(const AES& aes, const Bytes& input, const Bytes& iv, bool padding) {
    check_iv(iv);
    const Bytes data = padding ? pad(input) : input;
    check_aligned(data);
    Bytes output;
    Block previous = block(iv, 0);
    for (std::size_t offset = 0; offset < data.size(); offset += AES::BLOCK_SIZE) {
        previous = aes.encrypt(xorblock(block(data, offset), previous));
        append(output, previous);
    }
    return output;
}

// CBC decryption uses the previous ciphertext block or the IV as feedback.
Bytes cbc_decrypt(const AES& aes, const Bytes& input, const Bytes& iv, bool padding) {
    check_iv(iv);
    check_aligned(input);
    Bytes output;
    Block previous = block(iv, 0);
    for (std::size_t offset = 0; offset < input.size(); offset += AES::BLOCK_SIZE) {
        const Block current = block(input, offset);
        append(output, xorblock(aes.decrypt(current), previous));
        previous = current;
    }
    return padding ? unpad(output) : output;
}

// Shared CFB implementation for encryption and decryption.
static Bytes cfb(const AES& aes, const Bytes& input, const Bytes& iv,
                 int segmentBits, bool encrypt) {
    check_iv(iv);
    if (segmentBits < 8 || segmentBits > 128 || segmentBits % 8 != 0) {
        throw std::invalid_argument("CFB segment bits must be 8..128 and byte-aligned");
    }
    const std::size_t segment = static_cast<std::size_t>(segmentBits / 8);
    Block reg = block(iv, 0);
    Bytes output;
    for (std::size_t offset = 0; offset < input.size(); offset += segment) {
        const Block stream = aes.encrypt(reg);
        const std::size_t count = std::min(segment, input.size() - offset);
        for (std::size_t i = 0; i < count; ++i) output.push_back(input[offset + i] ^ stream[i]);
        if (count == segment) {
            for (std::size_t i = 0; i < AES::BLOCK_SIZE - segment; ++i) reg[i] = reg[i + segment];
            for (std::size_t i = 0; i < segment; ++i) reg[AES::BLOCK_SIZE - segment + i] =
                encrypt ? output[offset + i] : input[offset + i];
        }
    }
    return output;
}

// CFB encryption with a byte-aligned segment size.
Bytes cfb_encrypt(const AES& aes, const Bytes& input, const Bytes& iv, int bits) {
    return cfb(aes, input, iv, bits, true);
}

// CFB decryption with a byte-aligned segment size.
Bytes cfb_decrypt(const AES& aes, const Bytes& input, const Bytes& iv, int bits) {
    return cfb(aes, input, iv, bits, false);
}

// OFB generates a keystream by repeatedly encrypting the feedback block.
Bytes ofb_crypt(const AES& aes, const Bytes& input, const Bytes& iv) {
    check_iv(iv);
    Block feedback = block(iv, 0);
    Bytes output;
    for (std::size_t offset = 0; offset < input.size(); offset += AES::BLOCK_SIZE) {
        feedback = aes.encrypt(feedback);
        const std::size_t count = std::min<std::size_t>(AES::BLOCK_SIZE, input.size() - offset);
        for (std::size_t i = 0; i < count; ++i) output.push_back(input[offset + i] ^ feedback[i]);
    }
    return output;
}

// CTR encrypts or decrypts by XORing with AES-encrypted counter blocks.
Bytes ctr_crypt(const AES& aes, const Bytes& input, const Bytes& initialCounter) {
    check_iv(initialCounter);
    Block counter = block(initialCounter, 0);
    Bytes output;
    for (std::size_t offset = 0; offset < input.size(); offset += AES::BLOCK_SIZE) {
        const Block stream = aes.encrypt(counter);
        const std::size_t count = std::min<std::size_t>(AES::BLOCK_SIZE, input.size() - offset);
        for (std::size_t i = 0; i < count; ++i) output.push_back(input[offset + i] ^ stream[i]);
        if (offset + AES::BLOCK_SIZE < input.size()) {
            for (int i = static_cast<int>(AES::BLOCK_SIZE) - 1; i >= 0; --i) {
                if (++counter[static_cast<std::size_t>(i)] != 0) {
                    break;
                }
            }
        }
    }
    return output;
}
}
