Sample C++ project for launching executables and out-of-process COM servers in a sandboxed [low integrity level (IL)](https://learn.microsoft.com/en-us/previous-versions/dotnet/articles/bb625960(v=msdn.10)) or [AppContainer](https://docs.microsoft.com/en-us/windows/desktop/secauthz/appcontainer-for-legacy-applications-) process on the *same machine*. There's no need to create any additional user accounts.

Related project: Microsoft [SandboxSecurityTools](https://github.com/microsoft/SandboxSecurityTools) for testing of AppContainer Sandboxing.

## RunInSandbox - Executable sandboxing
Run `RunInSandbox.exe [ac|li|mi|hi] [-b] ExePath <arguments>` to launch the `ExePath` application in an AppContainer, low IL, medium IL or high IL process. This works for `STARTUPINFOEX`-based process creation. The `-b` option is used to break execution immediately after process creation to enable debugging of startup problems.

## RunInSandbox - COM sandboxing
Run `RunInSandbox.exe [ac|li|mi|hi] [-g][-b] ProgID` to launch the `ProgID` COM server in an AppContainer, low IL, medium IL or high IL process. The `-g` option is used to grant AppContainer permissions for the COM server, which only need to be done once.

Example usage:
* `RunInSandbox.exe ac TestControl.TestControl -g` to start the TestControl project in a AppContainer process and test its COM API.
* `RunInSandbox.exe li PowerPoint.Application` to start Microsoft PowerPoint in a low IL process connected using COM automation.

#### Client-side impersonation
This approach performs client-side user impersonation with `ImpersonateLoggedOnUser` for the current thread. Then the COM server is created with `CLSCTX_ENABLE_CLOAKING` to allow the COM server to be created with the current thread credentials.

| | Token impersonation overview |
|---------------------|-----------------------------------------------------------------------------|
|Low integrity level  | Always works.                                            |
|AppContainer         | Works if `ALL_APPLICATION_PACKAGES` have been granted read&execute permissions for the COM EXE _and_ the corresponding `LaunchPermission` AppID registry key grant `ALL_APPLICATION_PACKAGES` local activation permission.  |

### Outstanding challenges
* How to apply `removableStorage` capability to enable USB stick access for the AppContainer.
* Why is `SetCursorPos` failing at medium IL _if_ the host is elevated (high IL). Impersonating the shell process (explorer.exe) to escape elevation doesn't seem to help. The problem appear to be caused by UIPI limitations tied to the foreground window.

## ComRunAs
Command-line tool for configuring COM servers to be started through a specific user account. Requires the COM server to already have an [`AppID`](https://learn.microsoft.com/en-us/windows/win32/com/appid-key) registry entry. Very similar to [dcompermex](https://github.com/albertony/dcompermex).

Instructions for how to [configure COM servers to always run elevated](ComElevation.md), either with or without UAC.

## GrantAccess
Command-line tool to make a file or path writable by AppContainers and low IL process. Useful for whitelisting specific folders that should not be subject to application sandboxing.

For serious usage, it's recommended to instead use [icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls) for tweaking file security settings, since icacls is a official Microsoft tool bundled with Windows.

Examples:
* `icacls.exe <path> /setintegritylevel Low` to make a file or folder writable from low IL processes.
* `icacls.exe <path> /grant *S-1-15-2-1:(OI)(CI)(F)` to grant [ALL_APP_PACKAGES](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab) full access to a given path.

## RunElevatedNet
C#/.Net sample code for launching an executable or COM class in an "elevated" process with admin privileges. The same functionality is also included in the RunInSandbox project.
