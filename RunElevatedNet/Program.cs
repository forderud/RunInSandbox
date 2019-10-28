using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using NetFwTypeLib; //for firewall sample


namespace RunElevatedNet
{
    /** Sample code for launching an executable or COM class in an "elevated" process with admin privileges.
        An User Account Control (UAC) prompt window will appear if the current process is not elevated.
        Uses either the "runas" verb or "COM Elevation Moniker" mechanism to achieve elevation. */
    class Program
    {
        static int Main(string[] args)
        {
            if (args.Length < 1) {
                System.Console.WriteLine("ERROR: COM class-id or executable filename argument missing");
                return 1;
            }

            // check if argument is a COM class
            Type comCls = Type.GetTypeFromProgID(args[0]); // e.g. HNetCfg.FwPolicy2

            if (comCls == null) {
                // argument is _not_ a COM CLSID, so assume that it's a EXE instead
                System.Console.WriteLine("Starting {0} in an elevated (admin) process...");
                ProcessStartInfo startInfo = new ProcessStartInfo(args[0]);
                startInfo.Verb = "runas"; // activate elevated invocation
                System.Diagnostics.Process.Start(startInfo);
                System.Console.WriteLine("[success]");
                return 0;
            }

#if false
            {
                System.Console.WriteLine("Creating a non-elevated (regular) COM class instance...");
                object obj = Activator.CreateInstance(comCls); // non-elevated
                System.Console.WriteLine("[success]");

                try {
                    TestFirewall((INetFwPolicy2)obj);
                } catch (InvalidCastException) {
                    // skip firewall testing
                }
            }
#endif
            {
                System.Console.WriteLine("Creating an elevated (admin) COM class instance...");
                object obj = CoCreateInstanceAsAdmin((IntPtr)0, comCls); // elevated
                System.Console.WriteLine("[success]");

                try {
                    TestFirewall((INetFwPolicy2)obj);
                } catch (InvalidCastException) {
                    // skip firewall testing
                }
            }

            return 0;
        }


        /** This function will be triggered if creating the "HNetCfg.FwPolicy2" COM class. */
        static void TestFirewall (INetFwPolicy2 firewallPolicy)
        {
            System.Console.WriteLine("Testing Windows firewall API...");
            // list existing rules
            foreach (INetFwRule rule in firewallPolicy.Rules) {
                Console.WriteLine("Firewall rule:\n  Name: {0}\n  Desc: {1}\n  Ports: {2}", rule.Name, rule.Description ?? "", rule.LocalPorts);
            }

            {
                // create new rule
                Type ruleClass = Type.GetTypeFromProgID("HNetCfg.FWRule");
                INetFwRule rule = (INetFwRule)Activator.CreateInstance(ruleClass);
                rule.Name = "My HTTP server";
                rule.Protocol = 6; //NET_FW_IP_PROTOCOL_TCP
                rule.LocalPorts = "8080";
                rule.Enabled = true;
                rule.Action = NET_FW_ACTION_.NET_FW_ACTION_ALLOW;
                rule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
                // add new rule (throws UnauthorizedAccessException, unless firewallPolicy runs in an elevated process)
                //firewallPolicy.Rules.Add(rule);
            }
            System.Console.WriteLine("[success]");
        }


        /** https://docs.microsoft.com/nb-no/windows/win32/api/objidl/ns-objidl-bind_opts */
        [StructLayout(LayoutKind.Sequential)]
        struct BIND_OPTS3
        {
            public uint cbStruct;
            uint grfFlags;
            uint grfMode;
            uint dwTickCountDeadline;
            uint dwTrackFlags;
            public uint dwClassContext;
            uint locale;
            object pServerInfo; // will be passing null, so type doesn't matter
            public IntPtr hwnd;
        }

        /** https://docs.microsoft.com/en-us/windows/win32/api/objbase/nf-objbase-cogetobject */
        [DllImport("ole32", CharSet = CharSet.Unicode, ExactSpelling = true, PreserveSig = false)]
        [return: MarshalAs(UnmanagedType.Interface)]
        static extern object CoGetObject(string pszName, [In] ref BIND_OPTS3 pBindOptions, [In] [MarshalAs(UnmanagedType.LPStruct)] Guid riid);


        /** C# port of COM Elevation Moniker sample in https://docs.microsoft.com/en-us/windows/win32/com/the-com-elevation-moniker */
        [return: MarshalAs(UnmanagedType.Interface)]
        static object CoCreateInstanceAsAdmin(IntPtr parentWindow, Type comClass)
        {
            // B formatting directive: returns {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} 
            var monikerName = "Elevation:Administrator!new:" + comClass.GUID.ToString("B");

            var bo = new BIND_OPTS3();
            bo.cbStruct = (uint)Marshal.SizeOf(bo);
            bo.hwnd = parentWindow;
            bo.dwClassContext = 4; // CLSCTX_LOCAL_SERVER

            Guid unknownGuid = Guid.Parse("00000000-0000-0000-C000-000000000046"); // IUnknown
            var obj = CoGetObject(monikerName, ref bo, unknownGuid);
            return obj;
        }
    }
}
