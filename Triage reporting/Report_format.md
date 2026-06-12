Severity: CRITICAL HIGH MEDIUM LOW INFORMATIONAL


Executive Summary
This will include very high level information about the escalation/incidet
Should answer questions "who what when why and how" in a very non-technical way, including very limited technical details.
Root cause (in a non technical way understandable by high level executives)
One point should also include "Business Impact": detail how the issue critically impacted the business or how the business would have been impacted if attackers had succeeded in remediation.
Risk/Impact
Must include what happened(in a successful attack scenario) or what would happen(if remediated). This should include technical details
Think broad and long term effect rather than short term impact, for eg. how lateral movement can lead to DC and then ransomware, rather than just focusing on the malware execution impact
Root Cause
Include the detailed root cause of the incident and specify exactly what triggered this alert/incident.
Detailed Investigation
This should include all the technical details right from Initial Access to Final activity by attacker/malware
This should not contain just bullets like:
process.commandline
process.executable
file.path (This provides no information to the client by reading nor to the other analyst. Please avoid these standalone bullets)
The technical investigation should be in a story format  it should include all relevant details that is understandable by the client as well as other analyst.
The timeline should be forensically strong, all events must co-relate to each other.
In short it Should answer questions "who what when why and how" in a very technical way, 

Actions Taken by PKF team (assume what will you do in this case)
what actions are taken in response by the PKF team
Actions required from [client] team
what actions should be taken in response by the Client team
Recommendations for User/IT team
This section should be different from the Action required section
It should include what user or IT team must take precautions in future so that such incident do not happen again, not related to this alert but a very long term solution that really addresses the root cause of this issue
