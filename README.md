# Run in Sandbox
Work-in-progress C++ code for launching executables and out-of-process COM server in a sandboxed [low-integrity](https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/bb625960(v%3dmsdn.10)) or [AppContainer](https://docs.microsoft.com/en-us/windows/desktop/secauthz/appcontainer-for-legacy-applications-) process on the *same machine*. There's no need to create any additional user accounts.

## Executable sandboxing
Run `RunInSandbox.exe [ac|li|mi|hi] ExePath` to launch the `ExePath` application in an AppContainer, low-integrity, medium-integrity or high-integrity process. This works for `STARTUPINFOEX`-based process creation.

## COM sandboxing
Run `RunInSandbox.exe [ac|li|mi|hi] ProgID [username] [password]` to launch the `ProgID` COM server in an AppContainer, low-integrity, medium-integrity or high-integrity process. The process will also run through a different user if username&password are provided. Unfortunately, AppContainer isolation doesn't work yet. Also, user impersonation only works for administrator accounts.

Example usage:
* `RunInSandbox.exe li TestControl.TestControl` to start the TestControl project in a low-integrity process and test its COM API.
* `RunInSandbox.exe li PowerPoint.Application` to start Microsoft PowerPoint in a low-integrity process connected using COM automation.

#### Client-side impersonation problems
This approach performs client-side user impersonation with `ImpersonateLoggedOnUser` for the current thread. Then the COM server is created with `CLSCTX_ENABLE_CLOAKING` to allow the COM server to be created with the current thread credentials.

| | Token impersonation problems |
|---------------------|-----------------------------------------------------------------------------|
|Low integrity        | :white_check_mark: (confirmed to work)                                      |
|AppContainer         | :x: Process is created but CoGetClassObject activation gives E_ACCESSDENIED (*The machine-default permission settings do not grant Local Activation permission for the COM Server*)   |

<!--
| | User impersonation problems |
|---------------------|-----------------------------------------------------------------------------|
|Run as admin user    | :white_check_mark: (confirmed to work)                                      |
|Run as non-admin user| :x: E_ACCESSDENIED (General access denied error) launch error, unless local DCOM "launch" and "activation" permission are granted. Still fail with CO_E_SERVER_EXEC_FAILURE (Server execution failed) after launch & activation permissions are granted. |

WARNING: **Does not work yet**. Did submit StackOverflow [DCOM registration timeout when attempting to start a COM server through a different user](https://web.archive.org/web/20190112183231/https://stackoverflow.com/questions/54076028/dcom-registration-timeout-when-attempting-to-start-a-com-server-through-a-differ) question to request advise (link to cached version, since the question was deleted).

Partial work-around: Use [`RunAs`](https://docs.microsoft.com/en-us/windows/desktop/com/runas) registry key to manually configure the user to run through. This also configures environment variable & registry properly, but launches the process in session 0 which prevents UI display.

#### COAUTHINFO-based (DCOM) process creation problems
This approach passes a [`COSERVERINFO`](https://docs.microsoft.com/en-us/windows/win32/api/objidl/ns-objidl-coserverinfo) parameter when creating the COM server. This parameter contains `COAUTHINFO`/`COAUTHIDENTITY` structures with the desired username & password for the COM server.

WARNING: **Does not work yet**. The StackOverflow [CoCreateInstanceEx returns S_OK with invalid credentials on Win2003](https://stackoverflow.com/questions/10589440/cocreateinstanceex-returns-s-ok-with-invalid-credentials-on-win2003) question seem to cover the same problem.
-->

## GrantAccess
Command-line tool to make a file or path writable by AppContainers and low-integrity process. Useful for whitelisting specific folders that should not be subject to application sandboxing.


## RunElevatedNet
C#/.Net sample code for launching an executable or COM class in an "elevated" process with admin privileges. The same functionality is also included in the RunInSandbox project.

## External references
UAC related:
* [How User Account Control works](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)
* [Runas](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc771525(v=ws.11))
* [COM Elevation Moniker](https://docs.microsoft.com/en-us/windows/win32/com/the-com-elevation-moniker)
