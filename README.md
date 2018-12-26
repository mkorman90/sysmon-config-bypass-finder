## Sysmon configuration bypass finder

Find possible ways to bypass sysmon logging, given a specific configuration.

For example:
```bash
(sysmon) martin@pc:~$ analyze-sysmon-config configurations/sysmonconfig-export.xml
 
rule_type       description
--------------  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
ProcessCreate   Any CommandLine containing AcroRd32.exe" /CR
ProcessCreate   Any CommandLine containing AcroRd32.exe" --channel=
ProcessCreate   Any ParentCommandLine that ends with "-outc=C:\ProgramData\Dell\CommandUpdate\inventory.xml" "-logc=C:\ProgramData\Dell\CommandUpdate\scanerrs.xml" "-lang=en" "-enc=UTF-16"
NetworkConnect  Any Image with the name Spotify.exe
NetworkConnect  Any Image that ends with AppData\Roaming\Dropbox\bin\Dropbox.exe
NetworkConnect  Any Image with the name g2ax_comm_expert.exe
NetworkConnect  Any Image with the name g2mcomm.exe
NetworkConnect  Any Image with the name OneDrive.exe
NetworkConnect  Any Image with the name OneDriveStandaloneUpdater.exe
NetworkConnect  Any Image that ends with AppData\Local\Microsoft\Teams\current\Teams.exe
NetworkConnect  Any DestinationHostname that ends with microsoft.com
NetworkConnect  Any DestinationHostname that ends with microsoft.com.akadns.net
NetworkConnect  Any DestinationHostname that ends with microsoft.com.nsatc.net

```

## Notes
* The tool does not correlate between conditions, but I intend to add this feature in the future
* ProcessCreate and NetworkConnect are the only rule types that are searched for bypasses
* Written for python 3.7 (https://pythonclock.org/)
