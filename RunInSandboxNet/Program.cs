string progId;
if (args.Length > 0)
    progId = args[0];
else
    progId = "TestControl.TestControl"; // default COM server

var obj = Sandboxing.CoCreate(Sandboxing.SDDL_ML_LOW, progId);
obj = null;

GC.Collect();
GC.WaitForPendingFinalizers();
