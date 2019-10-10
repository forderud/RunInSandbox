#include <iostream>
#include <string>
#include <Windows.h>

/** RAII wrapper of Win32 "handle" objects. */
class HandleWrap {
public:
    HandleWrap(HANDLE h) : handle(h) {
    }

    ~HandleWrap() {
        if (handle) {
            CloseHandle(handle);
            handle = nullptr;
        }
    }

    operator HANDLE () {
        return handle;
    }

private:
    HandleWrap(const HandleWrap &) = delete;
    HandleWrap& operator = (const HandleWrap &) = delete;

    HANDLE handle = nullptr;
};


int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Device path argument mising\n";
        return -1;
    }

    std::string port = argv[1]; // e.g. "COM3";

    HandleWrap handle = CreateFileA(port.c_str(), GENERIC_READ | GENERIC_WRITE, /*no sharing*/0,
                                /*no security*/NULL, OPEN_EXISTING, /*no overlapped*/0, NULL);
    if (!handle) {
        std::cerr << "Unable to open " << port << "\n";
        return -1;
    }
    std::cout << "Sucessfully opened " << port << "\n";

    // attempt to write to device
    char buffer[] = "X";
    DWORD bytesWritten = 0;
    BOOL ok = WriteFile(handle, buffer, sizeof(buffer), &bytesWritten, /*no overlapped*/NULL);
    if (!ok || (bytesWritten == 0)) {
        std::cerr << "Write failed\n";
        return -1;
    }

    std::cout << "Write ok\n";
    return 0;
}
