#include <functional>
#include <string>
#include <cstdint>
#include <unordered_map>
namespace psplit {
   
    struct ProcMapAddress {
        uintptr_t start;
        uintptr_t end;
        std::string path;
    };

    struct ProcessData {
        std::string name;
        uint32_t pid;
        std::vector<ProcMapAddress> address_maps;
    };

    using Int32Watcher = std::function<void(int32_t)>;

    struct I32WatcherData {
        Int32Watcher watcher;
        uintptr_t address;
        uint32_t current;
        uint32_t last;
    };
    

    using StringWatcher = std::function<void(const std::string&)>;
    struct StringWatcherData {
        StringWatcher watcher;
        uintptr_t address;
        std::string current;
        std::string last;
    };


    template<typename T>
    using TemplateWatcher = std::function<void(const T&)>;
    template<typename T>
    struct TemplateWatcherData {
        TemplateWatcher<T> callback;
        uintptr_t address;
        T current;
        T last;
    };

    using U8Watcher = TemplateWatcher<uint8_t>;
    using U8WatcherData = TemplateWatcherData<uint8_t>;
    
    class Process {
    private:
        ProcessData data;
        std::vector<I32WatcherData> i32_watchers;
        std::vector<StringWatcherData> string_watchers;
    public:
        Process(ProcessData _data) : data(_data) {}
        ~Process() = default;
        // no copying, no moving.
        Process(const Process&) = delete;
        Process(Process&&) noexcept = delete;
        Process& operator=(const Process&) = delete;
        Process& operator=(const Process&&) noexcept = delete;
        
        uintptr_t find_signature_pointer(const unsigned char* signature, size_t signature_size, const std::string& dll);

        void add_address_watcher_int32(uintptr_t address, Int32Watcher watcher);
        void add_address_watcher_string(uintptr_t address, StringWatcher watcher);
        
        uintptr_t pointer_at_address(uintptr_t address);

        void begin_watching(int32_t ms_sleep);
    };

    Process find_process_with_map(std::string name, std::string map_name);
}
