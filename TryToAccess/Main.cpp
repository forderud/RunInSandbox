#include <iostream>
#include <string>
#include <Windows.h>
#include "../RunInSandbox/Sandboxing.hpp"
#include "../TestControl/ComSupport.hpp"
#include "../Testcontrol/Socket.hpp"



static void TryOpenFile (std::wstring path) {
    using Handle = Microsoft::WRL::Wrappers::HandleT<Microsoft::WRL::Wrappers::HandleTraits::HANDLETraits>; // INVALID_HANDLE_VALUE on failure

    Handle handle(CreateFile2(path.c_str(), GENERIC_READ | GENERIC_WRITE, /*no sharing*/0, OPEN_EXISTING, NULL));
    if (!handle.IsValid())
        throw std::runtime_error("Unable to open file");

    // attempt to read from device
    char buffer[1] = {};
    DWORD bytesRead = 0;
    BOOL ok = ReadFile(handle.Get(), buffer, sizeof(buffer), &bytesRead, /*no overlapped*/NULL);
    if (!ok || (bytesRead == 0))
        throw std::runtime_error("Read failed");

    // attempt to write to device
    buffer[0] = 'X';
    DWORD bytesWritten = 0;
    ok = WriteFile(handle.Get(), buffer, sizeof(buffer), &bytesWritten, /*no overlapped*/NULL);
    if (!ok || (bytesWritten == 0))
        throw std::runtime_error("Write failed");
}

static void TryNetworkConnection (const std::wstring& host, std::wstring port) {
    SocketWrap sock;
    if (!sock.TryToConnect(ToAscii(host), stoi(port)))
        throw std::runtime_error("unable to connect");
}

int wmain(int argc, wchar_t *argv[]) {
    if (argc < 2) {
        std::wcerr << L"Device path argument mising\n";
        return -1;
    }

    try {
        if (argc == 2) {
            TryOpenFile(argv[1]); // e.g. "COM3";
            std::wcout << L"File open, read & write succeeded\n";
        } else if (argc == 3) {
            TryNetworkConnection(argv[1], argv[2]);
            std::wcout << L"Network connection succeeded\n";
        }
    } catch (const std::exception & e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return -1;
    }

    return 0;
}
