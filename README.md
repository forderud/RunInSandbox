# Run in Sandbox
C++ code for launching executables and out-of-process COM server in a sandboxed [low-integrity](https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/bb625960(v%3dmsdn.10)) or [AppContainer](https://docs.microsoft.com/en-us/windows/desktop/secauthz/appcontainer-for-legacy-applications-) process on the *same machine*. There's no need to create any additional user accounts.

## Executable sandboxing
Run `RunInSandbox.exe [ac|li|mi|hi] ExePath` to launch the `ExePath` application in an AppContainer, low-integrity, medium-integrity or high-integrity process. This works for `STARTUPINFOEX`-based process creation.

## COM sandboxing
Run `RunInSandbox.exe [ac|li|mi|hi] ProgID` to launch the `ProgID` COM server in an AppContainer, low-integrity, medium-integrity or high-integrity process.

Example usage:
* `RunInSandbox.exe li TestControl.TestControl` to start the TestControl project in a low-integrity process and test its COM API.
* `RunInSandbox.exe li PowerPoint.Application` to start Microsoft PowerPoint in a low-integrity process connected using COM automation.

#### Client-side impersonation
This approach performs client-side user impersonation with `ImpersonateLoggedOnUser` for the current thread. Then the COM server is created with `CLSCTX_ENABLE_CLOAKING` to allow the COM server to be created with the current thread credentials.

| | Token impersonation overview |
|---------------------|-----------------------------------------------------------------------------|
|Low integrity        | :white_check_mark: Always works.                                            |
|AppContainer         | :heavy_exclamation_mark: Works if `ALL_APPLICATION_PACKAGES` have been granted read&execute permissions for the COM EXE _and_ the corresponding `LaunchPermission` AppID registry key grant `ALL_APPLICATION_PACKAGES` local activation permission.  |

### Outstanding challenges
* How to _append_ the DCOM `LaunchPermission` ACL instead of replacing it. Also, look for a less cryptic way of achieving the same.
* How to programatically enable/disable networking for the AppContainer.
* How to programatically enable removable media (USB stick) access for the AppContainer


## GrantAccess
Command-line tool to make a file or path writable by AppContainers and low-integrity process. Useful for whitelisting specific folders that should not be subject to application sandboxing.


## RunElevatedNet
C#/.Net sample code for launching an executable or COM class in an "elevated" process with admin privileges. The same functionality is also included in the RunInSandbox project.

## External references
UAC related:
* [How User Account Control works](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)
* [Runas](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc771525(v=ws.11))
* [COM Elevation Moniker](https://docs.microsoft.com/en-us/windows/win32/com/the-com-elevation-moniker)
