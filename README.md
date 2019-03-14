# Run in Sandbox
Work-in-progress C++ code for launching executables and out-of-process COM server in a sandboxed [low-integrity](https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/bb625960(v%3dmsdn.10)) or [AppContainer](https://docs.microsoft.com/en-us/windows/desktop/secauthz/appcontainer-for-legacy-applications-) environment on the *same machine*.

## Executable sandboxing
Run `RunInSandbox.exe ExePath` to launch the `ExePath` application in a AppContainer process. This works for `STARTUPINFOEX`-based process creation, but not when using a "LowBox" token for process creation.

## COM sandboxing
Run `RunInSandbox.exe [ac|li] ProgID [username] [password]` to launch the `ProgID` COM server in an AppContainer or low-integrity process. The process will also run through a different user if username&password are provided. Unfortunately, only the low-integrity part works correctly. Neither user impersonation nor AppContainer isolation works properly yet.

Example usage:
`RunInSandbox.exe li Excel.Application` to start Microsoft Excel in low-integrity mode.

#### Client-side impersonation problems
This approach performs client-side user impersonation with `ImpersonateLoggedOnUser` for the current thread. Then the COM server is created with `CLSCTX_ENABLE_CLOAKING` to allow the COM server to be created with the current thread credentials.

| Token impersonation problems|                                                                     |
|---------------------|-----------------------------------------------------------------------------|
|Low integrity        | :white_check_mark: (confirmed to work)                                      |
|AppContainer         | :x: Process is created but crashes immediately                              |

WARNING: **AppContainer-based "LowBox" token impersonation does not work**. A process is created, but it crashes immediately after launch.

| User impersonation problems|                                                                      |
|---------------------|-----------------------------------------------------------------------------|
|Run as user          | :white_check_mark: (confirmed to work)                                      |
|Environment variables| :x: Inherited from client process user (inconsistent with impersonated user)|
|Registry mounting    | :question: Unknown (might be problems also here)                            |

WARNING: **Does not work yet**. Have submitted StackOverflow [DCOM registration timeout when attempting to start a COM server through a different user](https://stackoverflow.com/questions/54076028/dcom-registration-timeout-when-attempting-to-start-a-com-server-through-a-differ) question to request advise.

Partial work-around: Use [`RunAs`](https://docs.microsoft.com/en-us/windows/desktop/com/runas) registry key to manually configure the user to run through. This also configures environment variable & registry properly, but launches the process in session 0, which is not desired.

#### COAUTHINFO-based (DCOM) process creation problems
This approach passes a [`COSERVERINFO`](https://docs.microsoft.com/en-us/windows/desktop/api/objidl/ns-objidl-_coserverinfo) parameter when creating the COM server. This parameter contains `COAUTHINFO`/`COAUTHIDENTITY` structures with the desired username & password for the COM server.

WARNING: **Does not work yet**. The StackOverflow [CoCreateInstanceEx returns S_OK with invalid credentials on Win2003](https://stackoverflow.com/questions/10589440/cocreateinstanceex-returns-s-ok-with-invalid-credentials-on-win2003) question seem to cover the same problem.

