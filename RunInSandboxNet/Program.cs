class RunInSandbox
{
    static void TestCreate(string level, Type clsid)
    {
        var obj = Sandboxing.CoCreate(level, clsid);

        // Exercise TestControl API
        var tc = (TestControl.ITestInterface)obj;
        if (tc != null)
        {
            bool isElevated, isHighIL;
            tc.IsElevated(out isElevated, out isHighIL);
            Console.WriteLine("High IL: " + isHighIL);

            Console.WriteLine("Username: " + tc.GetUsername());
        }
    }

    static void Main(string[] args)
    {
        string progId;
        if (args.Length > 0)
            progId = args[0];
        else
            progId = "TestControl.TestControl"; // default COM server


        //TestCreate(Sandboxing.SDDL_ML_MEDIUM, Type.GetTypeFromProgID(progId)!);
        TestCreate(Sandboxing.SDDL_ML_LOW, Type.GetTypeFromProgID(progId)!);

        // Run GC to ensure everything's cleaned up
        GC.Collect();
        GC.WaitForPendingFinalizers();
    }
}
