# Run in Sandbox
Work-in-progress code for launching executables and out-of-process COM server in a sandboxed environment on the *same machine*.

## Executable sandboxing
Run `RunInSandbox.exe ExePath  [username] [password]` to launch the `ExePath` application in a AppContainer process.

## COM sandboxing
Run `RunInSandbox.exe ProgID [ax|li] [username] [password]` to launch the `ProgID` COM server in an AppContainer or low-integrity process. Unfortunately, neither user impersonation nor AppContainer isolation works properly yet.

#### Client-side impersonation problems
This approach performs client-side user impersonation with `ImpersonateLoggedOnUser` for the current thread. Then the COM server is created with `CLSCTX_ENABLE_CLOAKING` to allow the COM server to be created with the current thread credentials.

| Problem             | Status                                                                      |
|---------------------|-----------------------------------------------------------------------------|
|Run as user          | :white_check_mark: (confirmed)                                              |
|Environment variables| :x: Inherited from client process user (inconsistent with impersonated user)|
|Registry mounting    | :question: Unknown (might be problems also here)                            |

WARNING: **Does not work yet**. Have submitted StackOverflow [DCOM registration timeout when attempting to start a COM server through a different user](https://stackoverflow.com/questions/54076028/dcom-registration-timeout-when-attempting-to-start-a-com-server-through-a-differ) question to request advise.

Work-around: Use [`RunAs`](https://docs.microsoft.com/en-us/windows/desktop/com/runas) registry key to manually configure the user to run through. This also configures environment variable & registry properly, but launches the process in session 0, which is not desired.

#### COAUTHINFO-based (DCOM) impersonation problems
This approach passes a `COSERVERINFO` parameter when creating the COM server. This parameter contains `COAUTHINFO`/`COAUTHIDENTITY` structures with the desired username & password for the COM server.

WARNING: **Does not work yet**. The StackOverflow [CoCreateInstanceEx returns S_OK with invalid credentials on Win2003](https://stackoverflow.com/questions/10589440/cocreateinstanceex-returns-s-ok-with-invalid-credentials-on-win2003) question seem to cover the same problem.

#### AppContainer impersonation problems
Have not been able to "connect" an [AppContainer](https://docs.microsoft.com/en-us/windows/desktop/secauthz/appcontainer-for-legacy-applications-) SID to a impersonation token.
