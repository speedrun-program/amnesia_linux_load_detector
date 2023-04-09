How to test this:

Compile amnesia_load_detector.cpp as an executable file and extra_memory.cpp as a shared object file.

Give cap_sys_ptrace and cap_kill capabilities to amnesia_load_detector.exe so it can read from and write to the game's memory.

    sudo setcap "cap_sys_ptrace=eip cap_kill=eip" '/path/to/amnesia_load_detector.exe'

Use LD_PRELOAD to run Amnesia with extra_memory.so.
For example, with Amnesia_NOSTEAM.bin.x86_64:

    LD_PRELOAD='/path/to/extra_memory_64.so' '/path/to/Amnesia_NOSTEAM.bin.x86_64'

after Amnesia is running, start amnesia_load_detector.exe from terminal.

    '/home/ubuntu/cpp_files/amnesia_injector2.exe'
