## Prerequisites

Elevated COM servers need to explicitly call `CoInitializeSecurity` in the COM server to enable lower privilege clients to connect. The assigned user also need to have sufficient filesystem permissions to start the server.


## Configure COM servers to run as admin _with_ UAC prompt

Read [COM Elevation Moniker](https://docs.microsoft.com/en-us/windows/win32/com/the-com-elevation-moniker) for instructions for how to use User Account Control (UAC) prompts to request admin privileges for a COM server. UAC is general is documented in [How User Account Control works](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)


Instructions:
* Build solution from Visual Studio.
* Run `TestControl.exe /regserver` from an admin command prompt. Then run `RunInSandbox.exe hi TestControl.TestControl` from a non-admin command prompt. This will trigger a UAC prompt (if UAC is enabled) before the COM server is started. The UAC prompt will require a password _if_ the current user is not an admin.

![UAC_prompt](UAC_prompt.png) ![UAC_prompt_pw](UAC_prompt_pw.png)  


## Configure COM servers to always run as admin _without_ UAC prompt

**WARNING**: This will introduce a privilege escalation vulnerability if not used carefully.

The [`HKCR\AppID\{APPID}\RunAs`](https://learn.microsoft.com/en-us/windows/win32/com/runas) registry value can be used to configure which user account is used for out-of-proc COM servers. This can be used to make a COM server always run with admin privileges without any UAC prompt.

Alternatives for editing the registry value:
* Edit registry with `regedit.exe`. This only works for accounts that doesn't require a password.
* Run `ComRunAs.exe <AppID> <username> <password>` to specify username & password.
* Edit manually using Component Services (`dcomcnfg.exe`).

In-built accounts that can be used _without_ password:
* [LocalService](https://learn.microsoft.com/en-us/windows/win32/services/localservice-account): `NT AUTHORITY\LocalService` - restricted user _without_ network identity
* [NetworkService](https://learn.microsoft.com/en-us/windows/win32/services/networkservice-account): `NT AUTHORITY\NetworkService` - restricted user _with_ network identity
* [LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account): `NT AUTHORITY\SYSTEM` - high privilege super user

![DCOM_RunAs](DCOM_RunAs.png)  

### Instructions to test
* Run `TestControl.exe /regserver` from an admin command prompt.
* Run `ComRunAs.exe {264FBADA-8FEF-44B7-801E-B728A1749B5A} "NT AUTHORITY\LocalService"` from an admin command prompt to configure TestControl to be launched through the LocalService account.
* To test, run `RunInSandbox.exe TestControl.TestControl` from a non-admin command prompt. This will trigger creation of a TestControl.exe under the specified account.
