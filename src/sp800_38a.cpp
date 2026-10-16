#include "sp800_38a.hpp"
#include <algorithm>

namespace lab {
Bytes ecb_encrypt(const AES& aes, const Bytes& input, bool padding) {
    const Bytes data = padding ? pad(input) : input; check_aligned(data); Bytes out;
    for (std::size_t i = 0; i < data.size(); i += 16) {
        append(out, aes.encrypt(block(data, i)));
    }
    return out;
}
Bytes ecb_decrypt(const AES& aes, const Bytes& input, bool padding) {
    check_aligned(input); Bytes out;
    for (std::size_t i = 0; i < input.size(); i += 16) append(out, aes.decrypt(block(input, i)));
    return padding ? unpad(out) : out;
}
Bytes cbc_encrypt(const AES& aes, const Bytes& input, const Bytes& iv, bool padding) {
    check_iv(iv); const Bytes data = padding ? pad(input) : input; check_aligned(data); Bytes out; Block previous = block(iv, 0);
    for (std::size_t i = 0; i < data.size(); i += 16) { previous = aes.encrypt(xorblock(block(data, i), previous)); append(out, previous); } return out;
}
Bytes cbc_decrypt(const AES& aes, const Bytes& input, const Bytes& iv, bool padding) {
    check_iv(iv); check_aligned(input); Bytes out; Block previous = block(iv, 0);
    for (std::size_t i = 0; i < input.size(); i += 16) { const Block current = block(input, i); append(out, xorblock(aes.decrypt(current), previous)); previous = current; }
    return padding ? unpad(out) : out;
}
static Bytes cfb(const AES& aes, const Bytes& input, const Bytes& iv, int bits, bool encrypt) {
    check_iv(iv); if (bits < 8 || bits > 128 || bits % 8 != 0) throw std::invalid_argument("CFB segment bits must be 8..128 and byte-aligned");
    const std::size_t n = static_cast<std::size_t>(bits / 8); Block register_value = block(iv, 0); Bytes out;
    for (std::size_t i = 0; i < input.size(); i += n) {
        const Block stream = aes.encrypt(register_value); const std::size_t take = std::min(n, input.size() - i);
        for (std::size_t j = 0; j < take; ++j) out.push_back(input[i + j] ^ stream[j]);
        if (take == n) { for (std::size_t j = 0; j < 16 - n; ++j) register_value[j] = register_value[j + n]; for (std::size_t j = 0; j < n; ++j) register_value[16 - n + j] = encrypt ? out[i + j] : input[i + j]; }
    } return out;
}
Bytes cfb_encrypt(const AES& aes, const Bytes& input, const Bytes& iv, int bits) { return cfb(aes, input, iv, bits, true); }
Bytes cfb_decrypt(const AES& aes, const Bytes& input, const Bytes& iv, int bits) { return cfb(aes, input, iv, bits, false); }
Bytes ofb_crypt(const AES& aes, const Bytes& input, const Bytes& iv) {
    check_iv(iv); Block feedback = block(iv, 0); Bytes out;
    for (std::size_t i = 0; i < input.size(); i += 16) { feedback = aes.encrypt(feedback); for (std::size_t j = 0; j < std::min<std::size_t>(16, input.size() - i); ++j) out.push_back(input[i + j] ^ feedback[j]); } return out;
}
Bytes ctr_crypt(const AES& aes, const Bytes& input, const Bytes& initial_counter) {
    check_iv(initial_counter); Block counter = block(initial_counter, 0); Bytes out;
    for (std::size_t i = 0; i < input.size(); i += 16) {
        const Block stream = aes.encrypt(counter); for (std::size_t j = 0; j < std::min<std::size_t>(16, input.size() - i); ++j) out.push_back(input[i + j] ^ stream[j]);
        if (i + 16 < input.size()) {
            for (int j = 15; j >= 0; --j) {
                if (++counter[static_cast<std::size_t>(j)] != 0) break;
            }
        }
    } return out;
}
}
