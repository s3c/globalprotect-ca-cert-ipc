c2us.exe - Launches a command as the running user in the desktop session of the logged on user. In thise case, launches cmd.exe as SYSTEM in the desktop session of the unprivileged user.
c2us.c - Source code for c2us.exe.

epinject.exe - Entry point injector, used to spawn a new process and inject code at its entrypoint. 
loadgpsend.bin - Payload injected into PanGPA.exe using epinject.exe, to run the main exploit body, c:\windows\temp\gpsend.dll

crypt.c - Crypto implementation compatible with Globalprotect.
gpcaupgrade.c - Main exploit code.
gpupgrade.dll - Main exploit DLL.

GlobalProtect.msi - Backdoored version of 6.3.2 installer. Uses c2us.exe to launch a SYSTEM shell when the exploit executes.

gpcaupgrade.bat - Run this to execute the exploit.

After the exploit runs there is a 120s delay before GP starts the update process, if the window doesn't close with errors the exploit failed. If it succeeds there should be some error messages before it closes, some windows flashing up and cmd.exe spawned as SYSTEM, can verify with the whoami command.