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

    /** Create COM server in a sandboxed process. */
    public static object CoCreate(string level, string progId)
    {
        // matches OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY)
        using WindowsIdentity token = WindowsIdentity.GetCurrent(TokenAccessLevels.Duplicate | TokenAccessLevels.AdjustDefault | TokenAccessLevels.Query | TokenAccessLevels.AssignPrimary);

        IntPtr sidPtr = IntPtr.Zero;
        if (!ConvertStringSidToSidW(level, out sidPtr))
            throw new Win32Exception("ConvertStringSidToSid failed");

        // reduce process integrity level
        var tokenMandatoryLabel = new TOKEN_MANDATORY_LABEL();
        tokenMandatoryLabel.Label.Attributes = 0x00000020; // SE_GROUP_INTEGRITY
        tokenMandatoryLabel.Label.Sid = sidPtr;

        int tokenMandatoryLabelSize = Marshal.SizeOf(tokenMandatoryLabel) + GetLengthSid(sidPtr);
        IntPtr tokenMandatoryLabelPtr = Marshal.AllocHGlobal(tokenMandatoryLabelSize);
        Marshal.StructureToPtr(tokenMandatoryLabel, tokenMandatoryLabelPtr, true);

        using var handle = new SafeProcessHandle(token.Token, false);
        if (!SetTokenInformation(handle, TokenInformationClass.TokenIntegrityLevel, tokenMandatoryLabelPtr, tokenMandatoryLabelSize))
            throw new Win32Exception("SetTokenInformationStruct failed");

        return WindowsIdentity.RunImpersonated(token.AccessToken, () =>
        {
            return Activator.CreateInstance(Type.GetTypeFromProgID(progId));
        });
    }

    [DllImport("Advapi32.dll", SetLastError = true)]
    private static extern bool SetTokenInformation(
                                SafeProcessHandle TokenHandle,
                                TokenInformationClass TokenInformationClass,
                                IntPtr TokenInformation,
                                int TokenInformationLength);


    private enum TokenInformationClass
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        MaxTokenInfoClass  // MaxTokenInfoClass should always be the last enum
    }

    // Copied from https://github.com/dotnet/wpf-test/blob/main/src/Test/Common/Code/Microsoft/Test/Diagnostics/ProcessHelper.cs
    [StructLayout(LayoutKind.Sequential)]
    private class SID_AND_ATTRIBUTES
    {
        public SID_AND_ATTRIBUTES()
        {
            this.Sid = IntPtr.Zero;
        }

        public IntPtr Sid;
        public uint Attributes;
    }

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
    private static extern bool ConvertStringSidToSidW(string sid, out IntPtr psid);

    [DllImport("Advapi32.dll", CallingConvention = CallingConvention.Winapi)]
    private static extern int GetLengthSid(IntPtr pSid);

    [StructLayout(LayoutKind.Sequential)]
    private class TOKEN_MANDATORY_LABEL
    {
        public TOKEN_MANDATORY_LABEL()
        {
            this.Label = new SID_AND_ATTRIBUTES();
        }
        public SID_AND_ATTRIBUTES Label;
    }
}
