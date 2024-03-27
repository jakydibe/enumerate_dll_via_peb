This code contains 2 functions that 1)will enumerate the modules attached to a process 2)will return del DllBase address of a module given its name .

It does so by manually searching a module list through the structs in the PEB.
This is very useful because it can get the dlls witouth doing direct calls to the Windows API.

I wanted to do this little project since i found the classical ways to enumerate modules fails in certain circumstances.
