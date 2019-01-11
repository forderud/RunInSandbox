# COM Impersonation
Work-in-progress code for launching an out-of-process COM server through a different user on the *same machine*.

## Client-side impersonation approach
This approach performs client-side user impersonation with `ImpersonateLoggedOnUser` for the current thread. Then the COM server is created with `CLSCTX_ENABLE_CLOAKING` to allow the COM server to be created with the current thread credentials.

| Problem             | Status                                                                      |
|---------------------|-----------------------------------------------------------------------------|
|Run as user          | :white_check_mark: (confirmed)                                              |
|Environment variables| :x: Inherited from client process user (inconsistent with impersonated user)|
|Registry mounting    | :question: Unknown (might be problems also here)                            |

WARNING: **Does not work yet**. Have submitted StackOverflow [DCOM registration timeout when attempting to start a COM server through a different user](https://stackoverflow.com/questions/54076028/dcom-registration-timeout-when-attempting-to-start-a-com-server-through-a-differ) question to request advise.

Work-around: Use [`RunAs`](https://docs.microsoft.com/en-us/windows/desktop/com/runas) registry key to manually configure the user to run through. This also configures environment variable & registry properly, but launches the process in session 0, which is not desired.

## COAUTHINFO-based impersonation approach
This approach passes a `COSERVERINFO` parameter when creating the COM server. This parameter contains `COAUTHINFO`/`COAUTHIDENTITY` structures with the desired username & password for the COM server.

WARNING: **Does not work yet**. The StackOverflow [CoCreateInstanceEx returns S_OK with invalid credentials on Win2003](https://stackoverflow.com/questions/10589440/cocreateinstanceex-returns-s-ok-with-invalid-credentials-on-win2003) question seem to cover the same problem.
