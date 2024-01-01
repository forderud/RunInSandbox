/* This file is intended to match the C++ Sandboxing.hpp */

using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

class Sandboxing
{
    // DOC: https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings
    public static readonly string SDDL_ML_LOW = "LW"; // Low mandatory level
    public static readonly string SDDL_ML_MEDIUM = "ME"; // Medium integrity level

    /** Create COM server in a sandboxed process. */
    public static object CoCreate(string level, Type clsid)
    {
        // mimic OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT)
        using WindowsIdentity id = WindowsIdentity.GetCurrent(TokenAccessLevels.Duplicate | TokenAccessLevels.Impersonate | TokenAccessLevels.Query | TokenAccessLevels.AdjustDefault);
        using SafeAccessTokenHandle curToken = id.AccessToken;

        // mimic DuplicateTokenEx(curToken, 0, NULL, SecurityImpersonation, TokenImpersonation, &token)
        var token = new SafeAccessTokenHandle();
        if (!DuplicateTokenEx(curToken, 0, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TokenType.TokenImpersonation, ref token))
            throw new Win32Exception("DuplicateTokenEx failed");

        {
            IntPtr sidPtr = IntPtr.Zero;
            if (!ConvertStringSidToSidW(level, out sidPtr))
                throw new Win32Exception("ConvertStringSidToSid failed");

            // reduce integrity level
            var tokenMandatoryLabel = new TOKEN_MANDATORY_LABEL(sidPtr);
            int TokenIntegrityLevel = 25; // from TOKEN_INFORMATION_CLASS enum
            if (!SetTokenInformation(token, TokenIntegrityLevel, tokenMandatoryLabel, Marshal.SizeOf(tokenMandatoryLabel) + GetLengthSid(sidPtr)))
                throw new Win32Exception("SetTokenInformationStruct failed");

            Marshal.FreeHGlobal(sidPtr); // LocalFree wrapper
        }

        SafeAccessTokenHandle token2;
#if false
        using var id = new WindowsIdentity(token.DangerousGetHandle());
        token2 = id.AccessToken;
#else
        token2 = token;
#endif
        // RunImpersonated isn't actually needed here, since Process.Start & Activator.CreateInstance
        // are using the current process token, and _not_ the impersonation token.
        object obj = WindowsIdentity.RunImpersonated(token2, () =>
        {
            // process start
            Process.Start("notepad.exe");

            // COM server creation
            return Activator.CreateInstance(clsid);
        })!;

        token.Dispose();

        return obj;
    }

    // based on https://github.com/dotnet/wpf-test/blob/main/src/Test/Common/Code/Microsoft/Test/Diagnostics/ProcessHelper.cs
    [StructLayout(LayoutKind.Sequential)]
    private class SID_AND_ATTRIBUTES
    {
        public IntPtr Sid = IntPtr.Zero;
        public uint Attributes = 0x00000020; // SE_GROUP_INTEGRITY
    }

    [StructLayout(LayoutKind.Sequential)]
    private class TOKEN_MANDATORY_LABEL
    {
        public TOKEN_MANDATORY_LABEL(IntPtr sidPtr)
        {
            Label.Sid = sidPtr;
        }
        public SID_AND_ATTRIBUTES Label = new SID_AND_ATTRIBUTES();
    }

    [DllImport("Advapi32.dll", SetLastError = true)]
    private static extern bool SetTokenInformation(
                            SafeAccessTokenHandle TokenHandle,
                            int TokenInformationClass, // TOKEN_INFORMATION_CLASS enum
                            TOKEN_MANDATORY_LABEL TokenInformation,
                            int TokenInformationLength);

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern bool ConvertStringSidToSidW(string sid, out IntPtr psid);

    [DllImport("Advapi32.dll")]
    private static extern int GetLengthSid(IntPtr pSid);

    internal enum SECURITY_IMPERSONATION_LEVEL : uint
    {
        SecurityAnonymous = 0x0u,
        SecurityIdentification = 0x1u,
        SecurityImpersonation = 0x2u,
        SecurityDelegation = 0x3u,
    }

    internal enum TokenType : int
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    [DllImport("Advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(
                                  SafeAccessTokenHandle hExistingToken,
                                  TokenAccessLevels dwDesiredAccess,
                                  IntPtr lpTokenAttributes,   // LPSECURITY_ATTRIBUTES,
                                  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
                                  TokenType TokenType,
                                  ref SafeAccessTokenHandle phNewToken);
}
