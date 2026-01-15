# CyberSecurity-Attack-Defense-Lab
Designed a Purple Team environment to simulate multi-stage attacks, using various security tools to test and refine log aggregation within an implemented SIEM solution.


<u>File Integrity Monitoring Options Tested</u>
Event Type | realtime Alert | check_all (Metadata) | report_changes (Diff)
File Created,Yes (Instant),Yes (Size/Perms),No (No baseline yet)
File Modified,Yes (Instant),Yes (Hash change),Yes (Shows the edit)
File Deleted,Yes (Instant),Yes (Removal),No (File is gone)
