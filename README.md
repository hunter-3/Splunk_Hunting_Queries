<h1>Splunk Hunting Queries</h1> Work in Progress
<h2>Requirements</h2>

Windows Event Code 4688, 4769, 4103 and 4104

<a href=https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>Sysmon</a> Installed with <a href=https://github.com/SwiftOnSecurity/sysmon-config>SwiftOnSecurity</a> XML config

PowerShell Logging Enabled - <a href=https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5ba3dc87e79c703f9bfff29a/1537465479833/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2018+v2.2.pdf>Malware Archaeology</a> Cheat Sheet if you need a place to start

Event Code 4688 MUST log "Include command line in process creation events" in Group Policy

<H3>Splunk Hunting Queries</h3>

<h3>PowerShell</h3>

<b>PowerShell - Webclient and Download</b> > Log: Windows PowerShell Logging > Malware Archaelogy's <a href=https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5ba3dc87e79c703f9bfff29a/1537465479833/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2018+v2.2.pdf>Powershell Logging Cheat Sheet</a>

sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 (".Download" OR "Net.WebClient") NOT ("normal to your environment")
<br>| eval MessageA=split(Message,"):")</br> 
| eval MessageB=mvindex(MessageA,1)
<br>| eval MessageB=split(MessageB,"ScriptBlock ID:")</br>
| eval Message_Block=mvindex(MessageB,0)
<br>| table _time, host, ComputerName, User, TaskCategory, Message_Block</br>

<h3>Sysmon</h3>

<b>PowerShell - Webclient</b> > Log: Windows Sysmon > Sysmon Agent has to be deployed and configured with <a href=https://github.com/SwiftOnSecurity/sysmon-config>SwiftOnSecurity</a> Sysmon Config 

sourcetype="WinEventLog:Sysmon" CommandLine="*New-Object net.webclient*" 
<br>| stats values(CommandLine) by computer_name, user, parent_process,process</br>

<b> Downloaded PowerShell Script</b> > Log: Windows Sysmon

sourcetype=WinEventLog:Sysmon EventCode=15 Message="File stream created*" TargetFilename="*.ps1" 
<br>| stats VALUES(TargetFilename) by computer_name, Image, Hash</br>

<b> Encoded PowerShell Command</b> > Log: Windows Sysmon > Requires fine tuning by excluding items seen in your environment

sourcetype="WinEventLog:Sysmon" EventCode=1 "powershell.exe" CommandLine="*-en*" NOT (something known to your environment) 
<br>| sort 0 _time</br>
| table _time, host, domain, user, CommandLine, Company, ParentImage, file_hash

<h3>Windows</h3>

<b>Kerberoast</b> > Nice write up by <a href=https://www.trustedsec.com/2018/05/art_of_kerberoast/>Trusted Sec's Ben Ten</a>

(index=your_index) EventCode=4769 AND Service_Name!=krbtgt AND ServiceName!="*$"  AND Account_Name!="*$@yourdomain" AND Failure_Code=0x0 AND Ticket_Encryption_Type=0X17

<b>Registry Keys - Run and RunOnce</b> Log: Windows Security

sourcetype="WinEventLog:Security" EventCode=4657 Object_Name="*\\Run*" 
<br>| table _time, host, Security_ID, Account_Name, Account_Domain, Operation_Type, Object_Name, Object_Value_Name, Process_Name, New_Value</br>
