string progId;
if (args.Length > 0)
    progId = args[0];
else
    progId = "TestControl.TestControl"; // default COM server

var obj = Sandboxing.CoCreate(Sandboxing.SDDL_ML_LOW, progId);

{
    // Exercise TestControl API
    var tc = (TestControl.ITestInterface)obj;
    bool isElevated, isHighIL;
    tc.IsElevated(out isElevated, out isHighIL);
}

obj = null;

GC.Collect();
GC.WaitForPendingFinalizers();
