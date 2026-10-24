#include "dll.h"

#include <cstdint>
#include <fstream>
#include <ios>

bool psplit::open_dll_file(const std::string &path, psplit::DLLFile& out) {
    std::ifstream file(path, std::ios::in | std::ios::binary);
    if(!file.is_open())  
        return false;
    std::vector<std::byte> buffer;
    unsigned char current;
    while(file >> current)
        buffer.push_back(std::byte(current));
    if (buffer.empty()) { return false; }
    return true; 
}
