
How to test this:

Compile amnesia_load_detector.cpp as an executable file and extra_memory.cpp as a shared object file.

    g++ -O2 -o '/path/for/amnesia_load_detector.exe' '/path/to/amnesia_injector2.cpp'

    g++ -fPIC -shared -Os -o '/path/for/extra_memory_64.so' '/path/to/extra_memory.cpp'

    g++ -fPIC -m32 -shared -Os -o '/path/for/extra_memory_32.so' '/path/to/extra_memory.cpp'

Put timer_error_log.txt, mmap_file.txt, shared_file_name.txt, and byte_updates_per_second.txt in the directory you'll run amnesia_load_detector.exe from.
In shared_file_name.txt, write the filename you want to give mmap_file.txt.
In byte_updates_per_second.txt, write how many times per second you want amnesia_load_detector.exe to check if the game is in a load screen.

Give cap_sys_ptrace and cap_kill capabilities to amnesia_load_detector.exe so it can read from and write to the game's memory.

    sudo setcap "cap_sys_ptrace=eip cap_kill=eip" '/path/to/amnesia_load_detector.exe'

Use LD_PRELOAD to run Amnesia with extra_memory.so.
For example, with Amnesia_NOSTEAM.bin.x86_64:

    LD_PRELOAD='/path/to/extra_memory_64.so' '/path/to/Amnesia_NOSTEAM.bin.x86_64'

After Amnesia is running, start amnesia_load_detector.exe from terminal.

    '/home/ubuntu/cpp_files/amnesia_load_detector.exe'

When a load starts or finishes, a message should be printed.
