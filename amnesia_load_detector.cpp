
// this needs ptrace and signal capabilities to work.
// sudo setcap "cap_sys_ptrace=eip cap_kill=eip" '/path/to/amnesia_load_detector.exe'

// since cap_sys_ptrace and cap_kill are needed, this should be isolated as its own process, and interprocess communication should be used.

#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <errno.h>
#include <stdint.h>
#include <cstdio>
#include <string>
#include <memory>
#include <cstring>

const size_t fileBufferSize = 8192;
const size_t gameWriteSize = 16; // how many bytes to write to the three areas in game memory
// int pipefd = -1;

FILE* errorLog = nullptr;

class FileHelper
{
public:
    FileHelper(const FileHelper& fhelper) = delete;
    FileHelper& operator=(FileHelper other) = delete;
    FileHelper(FileHelper&&) = delete;
    FileHelper& operator=(FileHelper&&) = delete;
    
    FileHelper(const char* filename)
    {
        if (!(_f = fopen(filename, "rb")))
        {
            fprintf(errorLog, "FileHelper fopen failure in constructor: %d\n", errno);
        }
    }
    
    ~FileHelper()
    {
        if (_f)
        {
            fclose(_f);
        }
    }
    
    bool getCharacter(char& ch)
    {
        if (_bufferPosition == _charactersRead)
        {
            _bufferPosition = 0;
            _charactersRead = (int)fread(_buffer.get(), sizeof(char), fileBufferSize, _f);

            if (!_charactersRead)
            {
                return false;
            }
        }
        
        ch = _buffer[_bufferPosition];
        _bufferPosition++;
        
        return true;
    }

private:
    FILE* _f = nullptr;
    std::unique_ptr<char[]> _buffer = std::make_unique<char[]>(fileBufferSize);
    int _bufferPosition = 0;
    int _charactersRead = 0;
};

class ProcessHelper
{
public:
    uint64_t gameStartAddress = 0;
    uint64_t mmapAddress = 0;
    pid_t pid = 0;
    bool is64bit = false;
    
    ProcessHelper(pid_t pid_, uint64_t startPosition, uint64_t lengthOfMemory, uint64_t mmapAddress_, bool is64bit_)
    {
        pid = pid_;
        _pageSize = sysconf(_SC_PAGESIZE);
        _bufferPosition = _pageSize; // this initial value lets the first read happen on the first call to getByte
        _memoryOffset = startPosition - _pageSize; // this will increase to 0 on the first read
        _bytesLeft = lengthOfMemory;
        _local[0].iov_base = _loc.get();
        _local[0].iov_len = _pageSize;
        _remote[0].iov_base = (void*)_memoryOffset;
        _remote[0].iov_len = _pageSize;
        gameStartAddress = startPosition;
        mmapAddress = mmapAddress_;
        is64bit = is64bit_;
    }
    
    bool getByte(unsigned char& b)
    {
        if (_bytesLeft == 0)
        {
            return false;
        }
        
        if (_bufferPosition == _pageSize)
        {
            _bufferPosition = 0;
            _memoryOffset += _pageSize;
            _remote[0].iov_base = (void*)_memoryOffset;
            ssize_t bytesRead = process_vm_readv(pid, _local, 1, _remote, 1, 0);
            
            if (bytesRead < _pageSize || errno)
            {
                fprintf(errorLog, "ProcessHelper process_vm_readv error in getByte: %d\nat memory address: %zu\n", errno, _memoryOffset);
                errno = 0;
                return false;
            }
        }
        
        b = _loc[_bufferPosition];
        _bufferPosition++;
        _bytesLeft--;
        
        return true;
    }
    
    // process_vm_writev doesn't work, so PTRACE_POKEDATA is used instead
    bool writeBytes(unsigned char* bytes, size_t bytesToWrite, size_t location)
    {
        long successStatus = 0;
        size_t longsWritten = 0;
        for (size_t bytesWritten = 0; bytesWritten < bytesToWrite; bytesWritten += sizeof(long))
        {
            successStatus = ptrace(PTRACE_POKEDATA, pid, location, ((long*)bytes)[longsWritten]);
            location += sizeof(long);
            longsWritten++;
            
            if (successStatus == -1)
            {
                fprintf(errorLog, "ProcessHelper ptrace PTRACE_POKEDATA error: %d\nat memory address: %zu\n", errno, location);
                errno = 0;
                return false;
            }
        }
        
        return true;
    }
    
private:
    struct iovec _local[1];
    std::unique_ptr<unsigned char[]> _loc = std::make_unique<unsigned char[]>(sysconf(_SC_PAGESIZE));
    struct iovec _remote[1];
    int _bufferPosition = 0;
    size_t _memoryOffset = 0;
    size_t _bytesLeft = 0;
    long _pageSize = 0;
};

struct SavedInstructions
{
    unsigned char loadEndOriginalBytes[gameWriteSize]{};
    unsigned char menuLoadOriginalBytes[gameWriteSize]{};
    unsigned char mapLoadOriginalBytes[gameWriteSize]{};
    uint64_t loadEndLocation = 0;
    uint64_t menuLoadLocation = 0;
    uint64_t mapLoadLocation = 0;
};

bool findPid(pid_t& pid, std::string& pidString)
{
    const char* gameNames[4] = {
        "/Amnesia_NOSTEAM.bin.x86_64",
        "/Amnesia.bin.x86_64",
        "/Amnesia_NOSTEAM.bin.x86",
        "/Amnesia.bin.x86"
    };
    
    char pathBuffer[64]{};
    char fileTextBuffer[256]{};
    FILE* f = nullptr;
    
    struct dirent *directoryEntry;
    DIR* procDirectory = nullptr;
    if ((procDirectory = opendir("/proc")) == nullptr)
    {
        fprintf(errorLog, "error opening proc directory: %d", errno);
        return false;
    }
    
    while ((directoryEntry = readdir(procDirectory)))
    {
        size_t truncationCheck = snprintf(pathBuffer, sizeof(pathBuffer), "/proc/%s/cmdline", directoryEntry->d_name);
        if (truncationCheck >= sizeof(pathBuffer))
        {
            continue;
        }
        
        if (!(f = fopen(pathBuffer, "r")))
        {
            errno = 0;
            continue;
        }
        
        size_t bytesRead = fread(fileTextBuffer, sizeof(char), sizeof(fileTextBuffer), f);
        size_t filenameIndex = 0;
        size_t lastSlashIndex = 0;
        for (; fileTextBuffer[filenameIndex] != '\0' && filenameIndex < bytesRead; filenameIndex++)
        {
            if (fileTextBuffer[filenameIndex] == '/')
            {
                lastSlashIndex = filenameIndex;
            }
        }
        if (filenameIndex == bytesRead || lastSlashIndex == 0)
        {
            fclose(f);
            continue;
        }
        
        for (int i = 0; i < sizeof(gameNames) / sizeof(std::string); i++)
        {
            if (strcmp(gameNames[i], fileTextBuffer + lastSlashIndex) == 0)
            {
                fclose(f);
                pidString = directoryEntry->d_name;
                pid = stol(pidString);
                return true;
            }
        }
        
        fclose(f);
    }
    
    fprintf(errorLog, "Couldn't find game PID\n");
    return false;
}

bool getSingleLineFileText(std::string& fileTextString, const char* filepath)
{
    FILE* f = nullptr;
    if (!(f = fopen(filepath, "r")))
    {
        fprintf(errorLog, "fopen error: %d\nwith file: %s\n", errno, filepath);
        return false;
    }
    
    char ch = '\0';
    while ((ch = fgetc(f)) != EOF)
    {
        if (ch == '\n')
        {
            break;
        }
        fileTextString.push_back(ch);
    }
    
    fclose(f);
    
    return true;
}

// copy line if it might say the location of the game's memory or the mmap memory
bool getPotentialLine(FileHelper& fh, std::string& mapLine)
{
    mapLine.clear();
    
    char ch = '\0';
    bool thereAreMoreCharacters = false;
    
    char readPermission = '\0';
    char executePermission = '\0';
    char sharePermission = '\0';
    
    // copying memory region
    while ((thereAreMoreCharacters = fh.getCharacter(ch)))
    {
        mapLine.push_back(ch);
        if (ch == ' ')
        {
            break;
        }
    }
    if (!thereAreMoreCharacters)
    {
        mapLine.clear();
        return false;
    }
    
    // copying permissions
    fh.getCharacter(readPermission);    mapLine.push_back(readPermission);
    fh.getCharacter(ch);                mapLine.push_back(ch);
    fh.getCharacter(executePermission); mapLine.push_back(executePermission);
    fh.getCharacter(sharePermission);   mapLine.push_back(sharePermission);
    fh.getCharacter(ch);                mapLine.push_back(ch);
    
    // checking if permissions match what's being searched for
    // if they aren't, skip the line
    if (!(readPermission == 'r' && executePermission == 'x' && sharePermission == 'p'))
    {
        mapLine.clear();
        while (fh.getCharacter(ch))
        {
            if (ch == '\n')
            {
                return true;
            }
        }
        return false;
    }
    
    // copying offset
    while ((thereAreMoreCharacters = fh.getCharacter(ch)))
    {
        mapLine.push_back(ch);
        if (ch == ' ')
        {
            break;
        }
    }
    if (!thereAreMoreCharacters)
    {
        mapLine.clear();
        return false;
    }
    
    // going to the start of the file path
    while ((thereAreMoreCharacters = fh.getCharacter(ch)))
    {
        if (ch == '/')
        {
            break;
        }
        else if (ch == '\n')
        {
            mapLine.clear();
            return true;
        }
    }
    if (!thereAreMoreCharacters)
    {
        mapLine.clear();
        return false;
    }
    mapLine.push_back('/'); // add this for consistency in case EOF was reached with no '/' found
    
    // copying file path
    while (fh.getCharacter(ch))
    {
        if (ch == '\n')
        {
            return true;
        }
        mapLine.push_back(ch);
    }
    
    return false;
}

uint64_t hexStringToInt(std::string& s, size_t pos, char endChar)
{
    uint64_t n = 0;
    size_t strSize = s.size();
    for (char ch = s[pos]; pos < strSize && ch != endChar; ch = s[pos])
    {
        n <<= 4;
        n += ch - '0' - (('a' - '9' - 1) * (ch >= 'a'));
        pos++;
    }
    return n;
}

bool checkForFilenameMatch(std::string& filename, const char** gameNames, size_t howManyGameNames)
{
    for (int i = 0; i < howManyGameNames; i++)
    {
        if (strcmp(filename.data(), gameNames[i]) == 0)
        {
            return true;
        }
    }
    return false;
}

// check if a copied line says the location of the game's memory or the mmap memory
void checkPotentialLine(
    std::string& mapLine,
    std::string& mmapMemoryName,
    const char** gameNames,
    size_t howManyGameNames,
    uint64_t& gameStartAddress,
    uint64_t& gameEndAddress,
    uint64_t& mmapAddress,
    bool& is64bit)
{
    size_t endAddressStart = mapLine.find('-') + 1;
    size_t permissionStart = mapLine.find(' ', endAddressStart) + 1;
    size_t offsetStart = mapLine.find(' ', permissionStart) + 1;
    size_t filenameStart = mapLine.rfind('/');
    
    std::string filename = mapLine.substr(filenameStart);
    
    if (mmapAddress == UINT64_MAX && mapLine[permissionStart + 1] == 'w' && filename == mmapMemoryName)
    {
        mmapAddress = hexStringToInt(mapLine, 0, '-');
    }
    else if (gameStartAddress == UINT64_MAX && checkForFilenameMatch(filename, gameNames, howManyGameNames))
    {
        gameStartAddress = hexStringToInt(mapLine, 0, '-') + hexStringToInt(mapLine, offsetStart, ' ');
        gameEndAddress = hexStringToInt(mapLine, endAddressStart, ' ');
        is64bit = (filename[filename.size() - 2] == '6' && filename[filename.size() - 1] == '4');
    }
}

void findPageLocations(
    std::string& pidString,
    std::string& mmapMemoryName,
    uint64_t& gameStartAddress,
    uint64_t& gameEndAddress,
    uint64_t& mmapAddress,
    bool& is64bit)
{
    std::string mapFileLocation("/proc/");
    mapFileLocation += pidString;
    mapFileLocation += {'/', 'm', 'a', 'p', 's', '\0'};
    
    FileHelper fh(mapFileLocation.data());
    
    // 64 bit names stored in front, 32 bit names stored in back
    const char* gameNames[4] = {
        "/Amnesia_NOSTEAM.bin.x86_64",
        "/Amnesia.bin.x86_64",
        "/Amnesia_NOSTEAM.bin.x86",
        "/Amnesia.bin.x86"
    };
    std::string mapLine;
    while (getPotentialLine(fh, mapLine))
    {
        if (!mapLine.empty())
        {
            checkPotentialLine(
                mapLine,
                mmapMemoryName,
                gameNames,
                sizeof(gameNames) / sizeof(char*),
                gameStartAddress,
                gameEndAddress,
                mmapAddress,
                is64bit
            );
        }
        
        if (gameStartAddress != UINT64_MAX && gameEndAddress != UINT64_MAX && mmapAddress != UINT64_MAX)
        {
            return;
        }
    }
}

void addNewValueToMemorySlice(unsigned char* memorySlice, size_t size, unsigned char newEndValue)
{
    for (int i = 0; i < size - 1; i++)
    {
        memorySlice[i] = memorySlice[i + 1];
    }
    memorySlice[size - 1] = newEndValue;
}

// this is fast enough for the size of the game
// if it needs to be faster, try making memorySlice a circular buffer
bool findInstructions(SavedInstructions& si, ProcessHelper& ph, bool& memoryReadSucceeded)
{
    unsigned char b = 0;
    unsigned char memorySlice[16]{}; // set this to at least the size of the longest byte pattern
    
    // first value is the size
    // other values are positions and byte values
    // i.e. {size, position, byteValue, position, byteValue, position, byteValue}
    unsigned char loadEndMatch32[] = {7, 0, 0xc1, 2, 0x1f, 11, 0x03};
    unsigned char menuLoadMatch32[] = {9, 0, 0xc7, 4, 0x02, 8, 0x8d, 15, 0x02};
    unsigned char mapLoadMatch32[] = {11, 0, 0x8b, 3, 0x8b, 9, 0xec, 10, 0x04, 11, 0x8b};
    unsigned char loadEndMatch64[] = {7, 0, 0xf2, 4, 0x08, 5, 0x41};
    unsigned char menuLoadMatch64[] = {7, 0, 0x4d, 2, 0xe1, 5, 0xfe};
    unsigned char mapLoadMatch64[] = {7, 0, 0xff, 3, 0x4c, 12, 0x4f};
    
    // the byte patterns should be behind the injection points
    unsigned char forwardOffsets[6] = {27, 82, 91, 29, 29, 54};
    unsigned char* matches[6] = {loadEndMatch32, menuLoadMatch32, mapLoadMatch32, loadEndMatch64, menuLoadMatch64, mapLoadMatch64};
    unsigned char copiedBytes[3][gameWriteSize]{}; // {loadEnd, menuLoad, mapLoad};
    uint64_t locations[3]{};
    
    for (int i = 1; i < sizeof(memorySlice); i++)
    {
        memoryReadSucceeded = ph.getByte(b);
        if (!memoryReadSucceeded)
        {
            return false;
        }
        memorySlice[i] = b;
    }
    
    for (size_t i = sizeof(memorySlice); (ph.getByte(b)) && (locations[0] == 0 || locations[1] == 0 || locations[2] == 0); i++)
    {
        addNewValueToMemorySlice(memorySlice, sizeof(memorySlice), b);
        for (int j = 0; j < (sizeof(locations) / sizeof(uint64_t)); j++)
        {
            if (locations[j] != 0)
            {
                continue;
            }
            bool matchFound = true;
            unsigned char* match = matches[j + (ph.is64bit * 3)];
            for (int k = 1; k < match[0]; k += 2)
            {
                if (memorySlice[match[k]] != match[k + 1])
                {
                    matchFound = false;
                    break;
                }
            }
            if (matchFound)
            {
                unsigned char forwardOffset = forwardOffsets[j + (ph.is64bit * 3)];
                for (size_t k = 0; k < forwardOffset; k++)
                {
                    ph.getByte(b);
                    addNewValueToMemorySlice(memorySlice, sizeof(memorySlice), b);
                }
                i += forwardOffset;
                
                // checking if the game was already injected
                if ((!ph.is64bit && memorySlice[0] == 0xe9) || (
                    ph.is64bit
                    && memorySlice[0] == 0x51
                    && memorySlice[1] == 0x48
                    && memorySlice[2] == 0xb9))
                {
                    return false;
                }
                
                std::memcpy(&copiedBytes[j], memorySlice, gameWriteSize);
                locations[j] = ph.gameStartAddress + i - sizeof(memorySlice);
            }
        }
    }
    
    si.loadEndLocation = locations[0];
    si.menuLoadLocation = locations[1];
    si.mapLoadLocation = locations[2];
    std::memcpy(si.loadEndOriginalBytes, &copiedBytes[0], gameWriteSize);
    std::memcpy(si.menuLoadOriginalBytes, &copiedBytes[1], gameWriteSize);
    std::memcpy(si.mapLoadOriginalBytes, &copiedBytes[2], gameWriteSize);
    
    return true;
}

bool writeInstructions64(SavedInstructions& si, ProcessHelper& ph)
{
    uint64_t jumpBackLocation = 0;
    unsigned char* gameOriginalBytes[3] = {si.loadEndOriginalBytes, si.menuLoadOriginalBytes, si.mapLoadOriginalBytes};
    uint64_t gameLocations[3] = {si.loadEndLocation, si.menuLoadLocation, si.mapLoadLocation};
    uint64_t mmapSectionLocations[3]{};
    size_t gameCopySizes[3] = {14, 14, 14};
    uint64_t mmapIndex = 1;
    uint32_t timerByteOffset = 0;
    
    unsigned char jmpToMmap[] = {
        0x51,                                                       // push rcx
        0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, mmapAddress
        0xff, 0xe1,                                                 // jmp rcx
        0x59                                                        // pop rcx
    };
    
    // ptrace needs to be used to write to the game's executable pages, and it copies one word at a time,
    // so this needs to be divisible by the word size
    unsigned char gameCopyBuffer[gameWriteSize]{};
    
    unsigned char bytesForMmap[128]{};
    // memset(&bytesForMmap[1], 0xcc, 127); // debugging
    
    // mov byte ptr [rip - timerByteOffset], timerByteNewValue
    unsigned char updateTimerByte[] = {0xc6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    unsigned char jmpBackToGame[] = {
        0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, originalGameAddress
        0xff, 0xe1                                                  // jmp rcx
    };
    
    // writing instructions for mmap memory
    for (int i = 0; i < (sizeof(mmapSectionLocations) / sizeof(uint64_t)); i++)
    {
        mmapSectionLocations[i] = mmapIndex;
        timerByteOffset = -mmapIndex - sizeof(updateTimerByte);
        memcpy(&updateTimerByte[2], &timerByteOffset, sizeof(timerByteOffset));
        updateTimerByte[sizeof(updateTimerByte) - 1] = i;
        memcpy(&bytesForMmap[mmapIndex], updateTimerByte, sizeof(updateTimerByte));
        memcpy(&bytesForMmap[mmapIndex + sizeof(updateTimerByte)], gameOriginalBytes[i], gameCopySizes[i]);
        jumpBackLocation = gameLocations[i] + sizeof(jmpToMmap) - 1;
        memcpy(&jmpBackToGame[2], &jumpBackLocation, sizeof(jumpBackLocation));
        memcpy(
            &bytesForMmap[mmapIndex + sizeof(updateTimerByte) + gameCopySizes[i]],
            jmpBackToGame,
            sizeof(jmpBackToGame)
        );
        mmapIndex += sizeof(updateTimerByte) + gameCopySizes[i] + sizeof(jmpBackToGame);
    }
    bytesForMmap[mmapSectionLocations[0] + 15] += 8; // fixing RSP offset
    bytesForMmap[mmapSectionLocations[1] + 14] += 8; // fixing RSP offset
    
    // rip relative addressing needs to be fixed here
    for (int i = 0; i < 20; i++)
    {
        bytesForMmap[mmapIndex + 6 - i] = bytesForMmap[mmapIndex - i];
    }
    uint32_t ripOffset = 0; memcpy(&ripOffset, &bytesForMmap[mmapSectionLocations[2] + 10], sizeof(ripOffset));
    size_t actualLocation = gameLocations[2] + 7 + ripOffset;
    bytesForMmap[mmapSectionLocations[2] + 7] = 0x48;
    bytesForMmap[mmapSectionLocations[2] + 8] = 0xb9;
    memcpy(&bytesForMmap[mmapSectionLocations[2] + 9], &actualLocation, sizeof(actualLocation));
    bytesForMmap[mmapSectionLocations[2] + 17] = 0x48;
    bytesForMmap[mmapSectionLocations[2] + 18] = 0x8b;
    bytesForMmap[mmapSectionLocations[2] + 19] = 0x01;
    mmapIndex += 6;
    
    ptrace(PTRACE_SEIZE, ph.pid, nullptr, nullptr); // process is already stopped
    
    // copying mmap instructions to mmap
    if (!ph.writeBytes(bytesForMmap, sizeof(bytesForMmap), ph.mmapAddress))
    {
        return false;
    }
    
    // writing the jumps to the mmap instructions in the game's memory
    for (int i = 0; i < (sizeof(mmapSectionLocations) / sizeof(uint64_t)); i++)
    {
        size_t mmapJmpLocation = mmapSectionLocations[i] + ph.mmapAddress;
        memcpy(&jmpToMmap[3], &mmapJmpLocation, sizeof(mmapJmpLocation));
        memcpy(gameCopyBuffer, gameOriginalBytes[i], sizeof(gameCopyBuffer));
        memcpy(gameCopyBuffer, jmpToMmap, sizeof(jmpToMmap));
        for (int j = sizeof(jmpToMmap); j < gameCopySizes[i]; j++)
        {
            gameCopyBuffer[j] = 0x90; // nop
        }
        if (!ph.writeBytes(gameCopyBuffer, sizeof(gameCopyBuffer), gameLocations[i]))
        {
            return false;
        }
    }
    
    ptrace(PTRACE_DETACH, ph.pid, nullptr, nullptr);
    
    return true;
}

bool writeInstructions32(SavedInstructions& si, ProcessHelper& ph)
{
    uint32_t jmpOffset = 0;
    unsigned char* gameOriginalBytes[3] = {si.loadEndOriginalBytes, si.menuLoadOriginalBytes, si.mapLoadOriginalBytes};
    uint32_t gameLocations[3] = {(uint32_t)si.loadEndLocation, (uint32_t)si.menuLoadLocation, (uint32_t)si.mapLoadLocation};
    uint32_t mmapSectionLocations[3]{};
    size_t gameCopySizes[3] = {5, 5, 5};
    uint32_t mmapAddress32 = (uint32_t)ph.mmapAddress;
    uint32_t mmapIndex = 1;
    
    unsigned char jmpInstruction[] = {0xe9, 0x00, 0x00, 0x00, 0x00}; // jmp mmap_instructions_offset
    
    // ptrace needs to be used to write to the game's executable pages, and it copies one word at a time,
    // so this needs to be divisible by the word size
    unsigned char gameCopyBuffer[gameWriteSize]{};
    
    unsigned char bytesForMmap[64]{};
    // memset(&bytesForMmap[1], 0xcc, 63); // debugging
    
    // last byte determines the value that the timer byte gets set to
    unsigned char updateTimerByte[] = {0xc6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00}; // mov byte ptr [mmapAddress], newValue
    memcpy(&updateTimerByte[2], &mmapAddress32, sizeof(mmapAddress32));
    
    // writing instructions for mmap memory
    for (int i = 0; i < (sizeof(mmapSectionLocations) / sizeof(uint32_t)); i++)
    {
        mmapSectionLocations[i] = mmapIndex + mmapAddress32;
        memcpy(&bytesForMmap[mmapIndex], updateTimerByte, sizeof(updateTimerByte));
        bytesForMmap[mmapIndex + sizeof(updateTimerByte) - 1] = i;
        memcpy(&bytesForMmap[mmapIndex + sizeof(updateTimerByte)], gameOriginalBytes[i], gameCopySizes[i]);
        jmpOffset = (gameLocations[i] + 5) - (mmapAddress32 + mmapIndex + sizeof(updateTimerByte) + gameCopySizes[i] + 5);
        memcpy(&jmpInstruction[1], &jmpOffset, sizeof(jmpOffset));
        memcpy(
            &bytesForMmap[mmapIndex + sizeof(updateTimerByte) + gameCopySizes[i]],
            jmpInstruction,
            sizeof(jmpInstruction)
        );
        mmapIndex += sizeof(updateTimerByte) + gameCopySizes[i] + sizeof(jmpInstruction);
    }
    
    ptrace(PTRACE_SEIZE, ph.pid, nullptr, nullptr); // process is already stopped
    
    // copying mmap instructions to mmap
    if (!ph.writeBytes(bytesForMmap, sizeof(bytesForMmap), ph.mmapAddress))
    {
        return false;
    }
    
    // writing the jumps to the mmap instructions in the game's memory
    for (int i = 0; i < (sizeof(mmapSectionLocations) / sizeof(uint32_t)); i++)
    {
        jmpOffset = mmapSectionLocations[i] - (gameLocations[i] + 5);
        memcpy(&jmpInstruction[1], &jmpOffset, sizeof(jmpOffset));
        memcpy(gameCopyBuffer, gameOriginalBytes[i], sizeof(gameCopyBuffer));
        memcpy(gameCopyBuffer, jmpInstruction, sizeof(jmpInstruction));
        for (int j = sizeof(jmpInstruction); j < gameCopySizes[i]; j++)
        {
            gameCopyBuffer[j] = 0x90; // nop
        }
        if (!ph.writeBytes(gameCopyBuffer, sizeof(gameCopyBuffer), gameLocations[i]))
        {
            return false;
        }
    }
    
    ptrace(PTRACE_DETACH, ph.pid, nullptr, nullptr);
    
    return true;
}

bool findAndWriteInstructions(SavedInstructions& si, ProcessHelper& ph)
{
    bool memoryReadSucceeded = false;
    bool needsToBeInjected = findInstructions(si, ph, memoryReadSucceeded);
    
    if (!memoryReadSucceeded)
    {
        return false;
    }
    else if (!needsToBeInjected)
    {
        fprintf(errorLog, "already injected instructions detected successfully\n");
        return true;
    }
    else if (!(si.loadEndLocation && si.mapLoadLocation && si.menuLoadLocation))
    {
        fprintf(errorLog, "couldn't find all instruction locations\n");
        return false;
    }
    
    bool injectionSucceeded = ph.is64bit ? writeInstructions64(si, ph) : writeInstructions32(si, ph);
    
    if (injectionSucceeded)
    {
        fprintf(errorLog, "game injected successfully\n");
    }
    
    return injectionSucceeded;
}

bool suspendAndInjectGame(pid_t& pid, size_t& mmapAddress, long& updatesPerSecond)
{
    uint64_t gameStartAddress = UINT64_MAX;
    uint64_t gameEndAddress = UINT64_MAX;
    bool is64bit = false;
    bool injectionSucceeded = false;
    
    SavedInstructions si;
    
    std::string mmapMemoryName;
    mmapMemoryName.push_back('/');
    getSingleLineFileText(mmapMemoryName, "shared_file_name.txt");
    
    std::string updatesPerSecondString;
    getSingleLineFileText(updatesPerSecondString, "byte_updates_per_second.txt");
    try
    {
        updatesPerSecond = std::stol(updatesPerSecondString);
    }
    catch (char const* e)
    {
        fprintf(errorLog, "Couldn't convert updatesPerSecondString. Error: %s\nDefaulting to %ld updates per second.", e, updatesPerSecond);
        return false;
    }
    if (updatesPerSecond < 1 || updatesPerSecond > 1000)
    {
        updatesPerSecond = updatesPerSecond < 1 ? 1 : 1000;
        fprintf(errorLog, "updatesPerSecond must be between an integer 1 and 1000. updatesPerSecond set to %ld\n", updatesPerSecond);
    }
    
    std::string pidString;
    bool pidFound = findPid(pid, pidString);
    if (!pidFound)
    {
        return false;
    }
    
    kill(pid, SIGSTOP);
    
    findPageLocations(pidString, mmapMemoryName, gameStartAddress, gameEndAddress, mmapAddress, is64bit);
    
    if (gameStartAddress == UINT64_MAX)
    {
        fprintf(errorLog, "couldn't find game executable memory\n");
        kill(pid, SIGCONT);
        return false;
    }
    if (mmapAddress == UINT64_MAX)
    {
        fprintf(errorLog, "couldn't find extra memory\n");
        kill(pid, SIGCONT);
        return false;
    }
    
    ProcessHelper ph(pid, gameStartAddress, gameEndAddress - gameStartAddress, mmapAddress, is64bit);
    
    injectionSucceeded = findAndWriteInstructions(si, ph);
    
    kill(pid, SIGCONT);
    
    return injectionSucceeded;
}

int main()
{
    pid_t pid = 0;
    long updatesPerSecond = 100;
    uint64_t mmapAddress = UINT64_MAX;
    unsigned char pipeByte = 0;
    
    if (!(errorLog = fopen("timer_error_log.txt", "w")))
    {
        printf("sigaction error: %d\n", errno);
        return 1;
    }
    /*
    if (mkfifo("timer_pipe_file", S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) != 0 && errno != EEXIST)
    {
        fprintf(errorLog, "mkfifo error: %d\n", errno);
        return 1;
    }
    errno = 0; // errno gets set if the pipe file already exists.
    if ((pipefd = open("timer_pipe_file", O_RDWR | O_NONBLOCK, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) < 0)
    {
        fprintf(errorLog, "open error: %d\n", errno);
        return 1;
    }
    */
    if (!suspendAndInjectGame(pid, mmapAddress, updatesPerSecond))
    {
        /*
        pipeByte = 0xff;
        flock(pipefd, LOCK_EX);
        size_t doNotWarn = write(pipefd, &pipeByte, sizeof(pipeByte));
        flock(pipefd, LOCK_UN);
        close(pipefd);
        */
        return 1;
    }
    
    unsigned char timerByteStorage[]{};
    struct iovec local[1];
    local[0].iov_base = timerByteStorage;
    local[0].iov_len = 1;
    struct iovec remote[1];
    remote[0].iov_base = (void*)mmapAddress;
    remote[0].iov_len = 1;
    
    const char* messages[3] = {
        "load end\n",
        "menu load\n",
        "map load\n"
    };
    
    struct timespec sleepTime = {1 * (updatesPerSecond == 1), (1000000000 / updatesPerSecond) * (updatesPerSecond != 1)};
    unsigned char previousTimerByteValue = 0;
    bool keepGoing = true;
    while (keepGoing)
    {
        nanosleep(&sleepTime, nullptr);
        int readvSucceeded = process_vm_readv(pid, local, 1, remote, 1, 0);
        
        /*
        flock(pipefd, LOCK_EX);
        while (read(pipefd, &pipeByte, sizeof(pipeByte)) != -1)
        {
            if (pipeByte == 0xff)
            {
                keepGoing = false;
                break;
            }
        }
        */
        keepGoing &= (readvSucceeded != -1);
        
        if (!keepGoing || readvSucceeded == -1)
        {
            printf("done\n");
        }
        else if ((pipeByte = ((unsigned char*)(local[0].iov_base))[0]) != previousTimerByteValue)
        {
            // ssize_t doNotWarn = write(pipefd, &pipeByte, sizeof(pipeByte));
            previousTimerByteValue = pipeByte;
            printf("%s", messages[pipeByte]);
        }
        // flock(pipefd, LOCK_UN);
    }
    
    /*
    pipeByte = 0xff;
    flock(pipefd, LOCK_EX);
    while (read(pipefd, &pipeByte, sizeof(pipeByte)) != -1);
    ssize_t doNotWarn = write(pipefd, &pipeByte, sizeof(pipeByte));
    flock(pipefd, LOCK_UN);
    close(pipefd);
    */
    fclose(errorLog);
    return 0;
}

