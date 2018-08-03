'Image Version Checker v1.0

On Error Resume Next
Dim WSHShell, strVersionNum
Set WSHShell = WScript.CreateObject("WScript.Shell")

strVersionNum = WSHShell.RegRead("HKLM\System\Setup\ImageBuild")

if (strVersionNum <> "") Then
 WSHShell.Popup "Image Build: " & strVersionNum 
Else
 WSHShell.Popup "Unknown Image Version!"
End If