
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>

static void* mmapAddress = MAP_FAILED;

__attribute__((constructor)) void mapNewPage()
{
    char mmapFileMessage[] = "x\n"; // the mmap file needs to have something in it, otherwise the program doesn't work
    
    int fd = open("mmap_file.txt", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    if (fd == -1)
    {
        return;
    }
    
    ssize_t writeSuccessStatus = write(fd, mmapFileMessage, sizeof(mmapFileMessage) - 1); // null character isn't needed
    if (writeSuccessStatus == -1)
    {
        close(fd);
        return;
    }
    
    mmapAddress = mmap(0, sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
    close(fd);
}

__attribute__((destructor)) void unmapPage()
{
    if (mmapAddress != MAP_FAILED)
    {
        munmap(mmapAddress, sysconf(_SC_PAGESIZE));
    }
}

