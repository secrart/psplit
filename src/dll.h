#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace psplit {
    // Class Rule: Rule of Zero.
    class DLLFile {
    private:
        std::vector<std::byte> buffer;
    public:
        // Searches across the DLL for a set of instructions matching the `data` parameter.
        // Parameter `data` is an array of size `data_size` and the first half defines a byte
        // while the second half represents a mask. A second half of 0xFF represents a "byte"
        // value, meaning we actually check. A second half of 0x00 represents a "mask" meaning
        // we don't care about the contents of this byte and it matches to anything. 
        uintptr_t search_for_function_signature(uint16_t* data, size_t data_size);
        // Read an address's value. Returned as a uintptr_t but it could be really any value.
        uintptr_t read_address(uintptr_t);
        // Fill the internal buffer with data (typically a DLL file's contents)
        void fill_buffer(std::vector<std::byte>& buffer);
    };

    bool open_dll(const std::string& path, DLLFile& out, bool read_following_unnamed);
}
