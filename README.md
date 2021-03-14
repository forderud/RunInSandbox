# Run in Sandbox
C++ code for launching executables and out-of-process COM servers in a sandboxed [low-integrity](https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/bb625960(v%3dmsdn.10)) or [AppContainer](https://docs.microsoft.com/en-us/windows/desktop/secauthz/appcontainer-for-legacy-applications-) process on the *same machine*. There's no need to create any additional user accounts.

## Executable sandboxing
Run `RunInSandbox.exe [ac|li|mi|hi] ExePath` to launch the `ExePath` application in an AppContainer, low-integrity, medium-integrity or high-integrity process. This works for `STARTUPINFOEX`-based process creation.

## COM sandboxing
Run `RunInSandbox.exe [ac|li|mi|hi] ProgID [-dnd] [-g]` to launch the `ProgID` COM server in an AppContainer, low-integrity, medium-integrity or high-integrity process. The `-dnd` option is used to enable OLE drag-and-drop through [RegisterDragDrop](https://docs.microsoft.com/en-us/windows/win32/api/ole2/nf-ole2-registerdragdrop) which causes problems for AppContainer sandboxing. The `-g` option is used to grant AppContainer permissions for the COM server, which only need to be done once.

Example usage:
* `RunInSandbox.exe ac TestControl.TestControl -g` to start the TestControl project in a AppContainer process and test its COM API.
* `RunInSandbox.exe li PowerPoint.Application` to start Microsoft PowerPoint in a low-integrity process connected using COM automation.

#### Client-side impersonation
This approach performs client-side user impersonation with `ImpersonateLoggedOnUser` for the current thread. Then the COM server is created with `CLSCTX_ENABLE_CLOAKING` to allow the COM server to be created with the current thread credentials.

| | Token impersonation overview |
|---------------------|-----------------------------------------------------------------------------|
|Low integrity        | Always works.                                            |
|AppContainer         | Works if `ALL_APPLICATION_PACKAGES` have been granted read&execute permissions for the COM EXE _and_ the corresponding `LaunchPermission` AppID registry key grant `ALL_APPLICATION_PACKAGES` local activation permission.  |

### Outstanding challenges
* Why is `RegisterDragDrop` triggering 0x80070005 "Access is denied" exception in the AppContainer process if the host is elevated (high-integrity level).
* How to apply `WinCapabilityRemovableStorageSid` to enable USB stick access for the AppContainer.
* Find solution for CoRegisterClassObject synchronization before calling CoCreateInstance, so that we can remove the arbitrary `Sleep`.
* Why is `SetCursorPos` failing at medium-integrity if the host is elevated (high-integrity level).


## GrantAccess
Command-line tool to make a file or path writable by AppContainers and low-integrity process. Useful for whitelisting specific folders that should not be subject to application sandboxing.


## RunElevatedNet
C#/.Net sample code for launching an executable or COM class in an "elevated" process with admin privileges. The same functionality is also included in the RunInSandbox project.

## External references
UAC related:
* [How User Account Control works](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)
* [Runas](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc771525(v=ws.11))
* [COM Elevation Moniker](https://docs.microsoft.com/en-us/windows/win32/com/the-com-elevation-moniker)
