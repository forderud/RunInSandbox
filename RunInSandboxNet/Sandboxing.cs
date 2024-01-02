/* This file is intended to match the C++ Sandboxing.hpp */

using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

class Sandboxing
{
    // DOC: https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings
    public static readonly string SDDL_ML_LOW = "LW"; // Low mandatory level
    public static readonly string SDDL_ML_MEDIUM = "ME"; // Medium integrity level

    /** Create COM server in a sandboxed process.
     *  WARNING: WindowsIdentity.GetCurrent throws "Access is denied" exception if called multiple times. */
    public static object CoCreate(string level, Type clsid)
    {
        // mimic OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT)
        using WindowsIdentity curId = WindowsIdentity.GetCurrent(TokenAccessLevels.Duplicate | TokenAccessLevels.Impersonate | TokenAccessLevels.Query | TokenAccessLevels.AdjustDefault);
        // mimic DuplicateTokenEx(curToken, 0, NULL, SecurityImpersonation, TokenImpersonation, &token)
        using var id = (WindowsIdentity)curId.Clone();
        using SafeAccessTokenHandle token = id.AccessToken;

        {
            IntPtr sidPtr = IntPtr.Zero;
            if (!ConvertStringSidToSidW(level, out sidPtr))
                throw new Win32Exception("ConvertStringSidToSid failed");

            // reduce integrity level
            var tokenMandatoryLabel = new TOKEN_MANDATORY_LABEL(sidPtr);
            int TokenIntegrityLevel = TokenIntegrityLevel = 25; // from TOKEN_INFORMATION_CLASS enum
            if (!SetTokenInformation(token, TokenIntegrityLevel, tokenMandatoryLabel, Marshal.SizeOf(tokenMandatoryLabel) + GetLengthSid(sidPtr)))
                throw new Win32Exception("SetTokenInformationStruct failed");

            Marshal.FreeHGlobal(sidPtr); // LocalFree wrapper
        }

        return WindowsIdentity.RunImpersonated(token, () =>
        {
            return Activator.CreateInstance(clsid);
        })!;
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
}
