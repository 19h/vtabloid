#pragma once
#include <vector>
#include <optional>
#include <cstring>
#include <string>
#include "types.hpp"

namespace Common {

    class BinaryView {
    public:
        // ImageBase can be 64-bit
        BinaryView(const std::vector<uint8_t>& data, uint64_t image_base)
            : data_(data), image_base_(image_base) {}

        template <typename T>
        std::optional<T> read(FileOffset offset) const {
            if (offset.value + sizeof(T) > data_.size()) return std::nullopt;
            T val;
            std::memcpy(&val, &data_[offset.value], sizeof(T));
            return val;
        }

        std::optional<std::string> read_string(FileOffset offset, size_t max_len = 256) const {
            if (offset.value >= data_.size()) return std::nullopt;
            size_t len = 0;
            while (offset.value + len < data_.size() && len < max_len) {
                if (data_[offset.value + len] == 0) break;
                len++;
            }
            if (len == max_len) return std::nullopt;
            return std::string(reinterpret_cast<const char*>(&data_[offset.value]), len);
        }

        const uint8_t* ptr(FileOffset offset) const {
            if (offset.value >= data_.size()) return nullptr;
            return &data_[offset.value];
        }

        size_t size() const { return data_.size(); }
        uint64_t image_base() const { return image_base_; }

    private:
        const std::vector<uint8_t>& data_;
        uint64_t image_base_;
    };
}