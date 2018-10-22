<h1>Splunk Hunting Queries</h1> Work in Progress
<h2>Requirements</h2>

Windows Event Code 4688, 4769, 4103 and 4104

<a href=https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>Sysmon</a> Installed with <a href=https://github.com/SwiftOnSecurity/sysmon-config>SwiftOnSecurity</a> XML config

PowerShell Logging Enabled - <a href=https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5ba3dc87e79c703f9bfff29a/1537465479833/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2018+v2.2.pdf>Malware Archaeology</a> Cheat Sheet if you need a place to start

Event Code 4688 MUST log "Include command line in process creation events" in Group Policy

<H3>Splunk Hunting Queries</h3>
