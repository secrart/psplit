#include "process.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include<iostream>
#include<fstream>


#include<dirent.h>

#include <sstream>
#include <stdexcept>
#include<sys/stat.h>
#include <sys/types.h>
#include<sys/uio.h>

#include <thread>
#include <vector>

const char* P_NAME = "hl2.exe";

bool read32(uint32_t pid, uintptr_t address, uint32_t& out) {
    iovec local{&out, sizeof out};
    iovec remote{reinterpret_cast<void*>(address), sizeof out};
    return process_vm_readv(pid, &local, 1, &remote, 1, 0) == sizeof out;
}

bool readstring(uint32_t pid, uintptr_t address, std::string& out) {
    char char_out;
    int32_t index = 0;
    iovec local {&char_out, sizeof char_out};
    iovec remote {reinterpret_cast<void*>(address), sizeof char_out};
    std::string result;

    // TODO: Read the whole string into a buffer and find the null terminator, lot's of syscalls here.
    while (char_out != '\0') {
        if(process_vm_readv(pid, &local, 1, &remote, 1, 0) != sizeof char_out) { return false; }
        result.push_back(char_out);
        index ++;
        remote.iov_base = reinterpret_cast<void*>(address + index);
    }
    out = result;
    return true;
}

uintptr_t psplit::Process::find_signature_pointer(const unsigned char *signature, size_t signature_size, const std::string& search_dll) {
    
    // find all the Mappings with the search_dll
    std::vector<ProcMapAddress> addresses;
    
    bool started_dll_load = false; // sometimes wine doesn't actually attribute all of the loaded DLL with it's path name, to circumvent this in the simplest way, we just load every following map that ISN'T named.
    bool finished_dll_load = false;
    std::copy_if(data.address_maps.begin(), data.address_maps.end(), std::back_inserter(addresses), [&](const ProcMapAddress& addr){ 
            if(finished_dll_load)
                return false;
            
            if(started_dll_load) {
                bool path_empty = addr.path.empty();
                
                if(!path_empty) {
                    finished_dll_load = true;
                    started_dll_load = false; // we're done, collapse the branch.
                }

                return path_empty; 
            } else {
                bool has_map = addr.path.find(search_dll) != std::string::npos;
                if (has_map) 
                    started_dll_load = true;

                return  has_map;
            }
        });

    bool found = false;
    for(const auto& address : addresses) {
        std::cout << "Searching for functionsig in " << search_dll << " at address " << std::hex << address.start << " -> " << address.end << std::endl;
        
        size_t size = address.end - address.start;
        std::vector<unsigned char> buffer(size);
        iovec local {buffer.data(), size};
        iovec remote {reinterpret_cast<void*> (address.start), address.end - address.start};
        process_vm_readv(data.pid, &local, 1, &remote, 1, 0);

        for(size_t i = 0; i < size && i + signature_size < address.end; i++ ) {
            for(size_t j = 0; j < signature_size; j++ ) {
                if(buffer[j + i] != signature[j] && signature[j] != 0x00) { // ? 0x00 is a mask
                    break;
                } else if (j == signature_size - 1) {
                    return address.start + i;
                }
            }
        }
    }
    std::cerr << "ERROR: COULDN'T LOCATE FUNCTION SIGNATURE" << std::endl;
    return 0; 
}

void psplit::Process::add_address_watcher_int32(uintptr_t address, Int32Watcher function) {
    I32WatcherData data;
    data.watcher = function;
    data.address = address;
    data.current = 0;
    data.last = 0;
    i32_watchers.push_back(data);
}

void psplit::Process::add_address_watcher_string(uintptr_t address, StringWatcher watcher) {
    StringWatcherData data;
    data.watcher = watcher;
    data.address = address;
    data.current = std::string();
    data.last = std::string();
    string_watchers.push_back(data);
}

uintptr_t psplit::Process::pointer_at_address(uintptr_t address) {
    uint32_t pointer; // 32bit process, TODO: MAKE THIS OPTIONAL
    iovec local {&pointer, sizeof pointer};
    iovec remote {reinterpret_cast<void*>(address), sizeof address};
    process_vm_readv(data.pid, &local, 1, &remote, 1, 0);
    return pointer;
}

void psplit::Process::begin_watching(int32_t ms_sleep) {
    
    while(true) {
        for (auto& stringWatcher: string_watchers) {
           std::string out;
           if(!readstring(data.pid, stringWatcher.address, out))
               continue;
           stringWatcher.current = out;
           if(stringWatcher.current != stringWatcher.last) {
                stringWatcher.watcher(out);
                stringWatcher.last = out;
           }
        }

        for(auto& i32watcher : i32_watchers) {
            uint32_t out = 0;
            if(!read32(data.pid, i32watcher.address, out)) {
                continue;
            } 
            i32watcher.current = out;
            if(i32watcher.current != i32watcher.last) {
                i32watcher.watcher(out);
                i32watcher.last = out;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(ms_sleep));
    }    
}

std::string get_proc_name(int32_t id) {

    std::stringstream ss;
    ss << "/proc/" << id << "/comm";

    std::ifstream file(ss.str());    
    
    if (!file.is_open()) {
        return "";
    } 
    
    std::string name;
    std::getline(file, name);
    return name;
}

std::vector<psplit::ProcessData> get_procs() {
    std::vector<psplit::ProcessData> result;    

    DIR* proc_dir = opendir("/proc/");
   
    dirent* dir;
    while((dir = readdir(proc_dir)) != nullptr) {
        // Don't let d_name fool you, this is the PROCESS ID, that's how these are sorted ofcourse.
        std::string id = dir->d_name;
        // Any failures of try are just skipped TODO: Maybe not?
        try {
            int32_t val = std::stoi(id);
            psplit::ProcessData data = {};
            data.pid = val;
            data.name = get_proc_name(val);
            result.push_back(data);
        } 
        catch (std::invalid_argument e) {
            continue;
        } 
        catch (std::out_of_range e) {
            std::cerr << "Big process ID, cannot handle" << std::endl;
            continue;
        }
    }
    
    closedir(proc_dir);
    return result;
}

std::ifstream get_proc_file(uint32_t pid, const std::string& child) {
    std::stringstream ss;
    ss << "/proc/" << pid << child;
    return std::ifstream(ss.str()); 
}

bool process_has_map(psplit::ProcessData process, const std::string& mapname) {
    std::stringstream ss;
    ss << "/proc/" << process.pid << "/maps";
    
    std::ifstream file(ss.str());
    if(!file.is_open())
        return false;
    
    std::string line;
    while(std::getline(file, line)) {
        auto iterate = line.find(mapname);
        if (iterate != std::string::npos) {
            return true;
        }
    }

    return false; 
}

struct MapsLine {
    
    std::string addresses, mode, offset, id, inode, path;

    bool any_empty() const { 
        return addresses.empty() || mode.empty() || offset.empty() || id.empty() || inode.empty() || path.empty();
    }

};

std::vector<psplit::ProcMapAddress> process_get_map_addresses(uint32_t pid) {
    std::vector<psplit::ProcMapAddress> map;
    
    std::ifstream file = get_proc_file(pid, "/maps");  
    if(!file.is_open())
        return {};
    std::string line; 
    while(std::getline(file, line)) {
        std::stringstream ss(line);

        MapsLine line;
        ss >> line.addresses;
        ss >> line.mode;
        ss >> line.offset;
        ss >> line.id;
        ss >> line.inode;
        ss >> line.path;

        ss.clear();
        ss.str(line.addresses);
        
        uintptr_t addresses[2];
        int32_t address_index = 0;

        std::string token;
        while(std::getline(ss, token, '-') && address_index < 2) { // Safety: address_index is locked to be under 2.
            addresses[address_index] = std::stoll(token, 0, 16); 
            address_index ++;
        }
        
        psplit::ProcMapAddress address;
        address.start = addresses[0];
        address.end = addresses[1];
        address.path = line.path;
        map.push_back(address);
    }
    return map;
}

// The main Wine process will have the engine.dll inside it's map.
psplit::Process psplit::find_process_with_map(std::string name, std::string mapname) {
    auto procs = get_procs();
    for (auto& proc : procs) {
        if(process_has_map(proc, mapname)) {
            std::cout << proc.pid << ": " << proc.name << std::endl;
            proc.address_maps = process_get_map_addresses(proc.pid);  
            return Process(proc); 
        }
    }    
    ProcessData fake_data = {};
    fake_data.pid = 0;
    fake_data.name = "";
    return psplit::Process(fake_data);
}
