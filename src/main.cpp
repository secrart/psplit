#include <cstddef>
#include <cstdint>
#include<iostream>

#include "process.h"

/*
 *  PSplit written by Secrart 2026
 *
 *
 *  This is a linux source engine autosplitter (as of now it's tailored toward SourceSplit Portal)
 *
 *  PROBLEMS: 
 *  - Fixed addresses: these could absolutely shift inbetween engine versions. EVEN game versions.
 *  - Fixed addresses: could shift inbetween loads of the hl2.exe.
 *  - CODE STYLE: This needs a rewrite honestly, wrote this on coffee at 2am.
 *
 *  TODOs:
 *  - Dynamically find the instructions that set these values upon load, THEN use those addresses
 * */


// the zeroes are masks. Our "GetApple()"
const unsigned char LOAD_STATE_SIG[] = 
{ 0x83, 0x3d, 0x00, 0x00, 0x00, 
  0x00, 0x02, 0x7d, 0x00, 0x33, 
  0xc0, 0x83, 0x3d, 0x00, 0x00, 
  0x00, 0x00, 0x06, 0x0f, 0x94, 
  0xc0, 0xc3 };

const uintptr_t LOAD_STATE_ADDRESS_SIG_OFFSET = 0x0D; // 13 bytes after the signature

const uintptr_t LOAD_STATE_ADDRESS = 0xf931d80;
const uintptr_t MAP_NAME_ADDRESS = 0xf8e5de1;

int main() {
    std::cout << "Starting PSplit" << std::endl;


    psplit::Process process = psplit::find_process_with_map("hl2.exe", "engine.dll");
    
    uintptr_t load_state_sig_pointer = process.find_signature_pointer(LOAD_STATE_SIG, sizeof LOAD_STATE_SIG, "engine.dll");

    std::cout << "Found signature at: " << std::hex << load_state_sig_pointer << std::endl;
    
    uintptr_t load_state_pointer = process.pointer_at_address(load_state_sig_pointer + LOAD_STATE_ADDRESS_SIG_OFFSET);
    
    std::cout << "Expected address: " << LOAD_STATE_ADDRESS << " Found address: " << load_state_pointer << std::endl;
    // watch the level load process
    process.add_address_watcher_int32(load_state_pointer, [] (int32_t address_data) {
        
        std::cout << "Load state detected: "  << address_data << std::endl;

    });

    process.add_address_watcher_string(MAP_NAME_ADDRESS, [] (const std::string& address_data) {
        std::cout << "Current Map: " << address_data << std::endl; 
    }); 
    process.begin_watching(1);
}
