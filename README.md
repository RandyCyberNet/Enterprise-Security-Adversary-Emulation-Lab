# CyberSecurity-Attack-Defense-Lab
Designed a Purple Team environment to simulate multi-stage attacks, using various security tools to test and refine log aggregation within an implemented SIEM solution.



These are some of the FIM options I tested and what worked, However, since this is a purple lab and want to focus more on getting visability I will keep the defult setting which logs all modification,addition, and deletion of files. However, it is not best practice becuase 
using the default FIM scanning will use a lot of cpu and disk usage becuase the scan will be done very minute, which in a real-environment a higher higher frequency time like <100sec> is not reccommeneed.
<u>File Integrity Monitoring Options Tested</u>
Event Type | realtime Alert | check_all (Metadata) | report_changes (Diff)
File Created,Yes (Instant),Yes (Size/Perms),No (No baseline yet)
File Modified,Yes (Instant),Yes (Hash change),Yes (Shows the edit)
File Deleted,Yes (Instant),Yes (Removal),No (File is gone)
