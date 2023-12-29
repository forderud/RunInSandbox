class RunInSandbox
{
    static void TestCreate(string level, string progId)
    {
        var obj = Sandboxing.CoCreate(level, progId);

        // Exercise TestControl API
        var tc = (TestControl.ITestInterface)obj;
        if (tc != null)
        {
            bool isElevated, isHighIL;
            tc.IsElevated(out isElevated, out isHighIL);
            Console.WriteLine("High IL: " + isHighIL);
        }
    }

    static void Main(string[] args)
    {
        string progId;
        if (args.Length > 0)
            progId = args[0];
        else
            progId = "TestControl.TestControl"; // default COM server


        TestCreate(Sandboxing.SDDL_ML_LOW, progId);

        // Run GC to ensure everything's cleaned up
        GC.Collect();
        GC.WaitForPendingFinalizers();
    }
}
