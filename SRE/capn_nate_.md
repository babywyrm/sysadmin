

Operational Excellence: SII Process
ThousandEyes Engineering
Cisco® ThousandEyes® Engineering
ThousandEyes Engineering

##
#
https://medium.com/thousandeyes-engineering/operational-excellence-sii-process-7ba5bf82092
#
##

Published in
Cisco® ThousandEyes® Engineering






by Nate Josway, Engineering Project Manager at Cisco ThousandEyes


Scenario
Imagine you stepped away from your desk to get a snack. It is a normal and uneventful day until a coworker comes into the break area and tells you that key parts of your company’s infrastructure that your team supports just crashed. What do you do? Will the situation continue to slide into chaos as teams try to respond to the problem, or will you calmly ask for an incident to be declared and use the incident management process to work through the problem?

Introduction
Incident management is a challenging topic. The processes for incident management needs to be clear and precise but flexible. A rigid framework will break if an edge case arises, while a relaxed framework will generate inconsistent results and may obscure the root cause of an incident. Finding the correct balance and maintaining that balance over time is a challenge for all incident management processes. Just like agile development methodologies, incident management processes are never static. Iterating on incident management is key to ensuring the processes can handle new challenges while maintaining consistent outcomes. Communication is critical in all stages of the incident management process. It is challenging to resolve an incident without clear and consistent communication. There is a time and place for silence while managing an incident but it is important to know when silence is a result of the response team focusing as opposed to the team waiting for instructions.

In the following sections, I will give you an overview of the incident management processes we use at ThousandEyes and explain why each stage of the process exists in its current form. I will also give background on important topics to consider during each stage of the incident management process. In each section, I will refer to Escalation Manager, Incident Commander, Customer Engineering Liaison, and responders roles.

Incident Management Roles

Escalation Manager - Escalation Managers are responsible for decisions the on-call personnel are not comfortable making themselves. Escalation Managers should always be notified of an incident regardless of the severity level.
Incident Commander - Typically the first responder or Escalation Manager assumes this role, but it may be given to another responder. Incident Commanders are the ultimate decision makers for an incident. They break decision deadlocks and have the authority to declare which actions the responders should follow. Incidents that last for a long period of time may have multiple Incident Commanders as shifts change. There should always be an Incident Commander, a chain of custody, and responsibility.
Scribe - A responder nominated to take notes for the timeline and to keep track of actions taken for the postmortem document.
Customer Engineering Liaison - Customer Engineering Liaisons update your company’s status page and help manage customer expectations during and after an incident.
Responders - Responders is the “everyone else” category. Responders include additional personnel that respond to mitigate the incident.
Declaring an Incident
The example used where something clearly breaks and causes a noticeable problem is not as common as you might think. The challenge is discovering the subtle problems that may not be enough to cause a noticeable incident on their own. Smaller problems can combine with other issues and trigger a major incident when left unresolved.

Declaring an incident may require additional information from other sources. Anyone should feel empowered to begin discussing if an issue is at the level of an incident. Larger problems with noticeable impact are typically higher severity incidents. Smaller issues may be difficult to assign to a severity level. The problem may be at risk of breaking an SLA or may have broken an SLA but in a limited or very localized way. When in doubt, start the incident management process. It is better to have a low-severity and low-impact incident rather than waiting to begin the process and increasing the risk of customer impact. Metrics and alerts can help determine if an incident needs to be declared. Setting and defining alert thresholds can help prevent incidents by triggering alerts before a problem impacts internal users or customers. Identifying an incident is easier if a metric exceeds the threshold for a previously determined amount of time. An alert should be triggered but oversight or edge cases can occur, which bypass or do not trigger an alert. Actively monitoring metric dashboards can help prevent these occurrences.

Classifying severity levels may vary depending on company process but the intent is usually the same for all incident management processes. For example, ThousandEyes uses P1, P2, P3, and P4 for classifying incident severity with P1 being a major incident and P4 being a very minor incident.

Managing an Incident
Managing an incident is paradoxically the easiest part of the incident management process. This is due to the incident management processes taking over and providing a strong process for responders to follow. The Escalation Manager will become the Incident Commander or nominate someone for the role. A scribe will be nominated and a Customer Engineering Liaison will be contacted, if one is not already participating in the incident response. The Incident Commander will lead the responders in diagnosing and resolving the incident. An important caveat is the amount of time required to resolve an incident. An incident with a clear root cause may take minutes to fix while another incident may require hours of investigation and experimentation to determine the root cause. The Incident Commander can declare the incident as resolved when the issue causing the incident is mitigated.

Resolving an Incident
An incident is considered resolved when the impact has been mitigated. Mitigating an incident means the responders have a clear understanding of the root cause and are able to apply temporary patches to safely resolve the immediate issue or solve the problem outright. The goal is to have enough knowledge and safety precautions in place to prevent a repeat incident.

Metrics should allow responders to determine when the impacted services have returned to their normal baseline. There are cases when a new baseline is established due to a temporary fix altering the state of a service. These situations should be monitored closely until a permanent fix is in place. Just like the other stages of an incident, communication at the resolution phase is critical. The responders should clearly communicate to the wider organization what changes were made and if the services were returned to their original state or if temporary fixes are in place. The reason for over-communicating is to ensure information is not siloed to a small group and that team members in different time zones have a clear understanding of what occurred. This may help others escalate a possible issue with a fix or avoid a false alarm if baseline metrics have changed.

Postmortem
The postmortem for an incident is an opportunity to reflect and understand how and why an incident occurred. Postmortems should be scheduled within 24 to 48 hours of an incident to allow the responders enough time to investigate the root cause and reflect on what occurred before, during, and after the incident. The meeting may be scheduled by the Escalation Manager or the person managing your incident processes. All of the responders should be required attendees but anyone should feel free to request an invitation. Postmortems are a place for everyone to learn more about an incident, not just those that responded to the incident. Creating user groups of stakeholders or interested individuals makes scheduling postmortems easier. Adding the user group and marking the individuals that did not participate in the incident as optional increases visibility for stakeholders and allows the option for others to attend. Sometimes a pivotal postmortem question or discussion topic comes from someone not involved in the response for the incident.

A postmortem document should have been created at the start of the incident. Adding information to the document during the incident should reduce the amount of information responders need to add to the document. Ideally, the majority of the timeline plus an overview of the impact and root cause means responders need to add clarification and additional information from learnings after the incident to the document. Adding information to the postmortem document can keep the meeting brief and to the point. Some companies may have internal incident management tooling or off the shelf tools that automate the creation of the postmortem document.

Determining the root cause is important, but the most important part of any postmortem is maintaining a “no blame” environment. Yes, someone probably checked-in a change or pushed a button that broke something but raking them over the proverbial coals creates a hostile environment and trains others to hide problems rather than calling out issues. It is important to remember that one person may have performed an action that triggered the incident, but many others performed actions which led up to the incident.

Reviewing the root cause and impact will take the most time during a postmortem meeting. Time should be spent asking why something occurred while reviewing the root cause since more action items may be discovered. There are a variety of techniques for root cause analysis, like the 5 Whys, which can be helpful. There may not be a significant number of action items depending on the severity of the incident. However, there are times where a low-severity incident uncovers a larger area of risk or shows that the root cause was in a different area.

Each postmortem will have action items. Each action item should be assigned to someone, preferably in the meeting, to own and drive the action item. Action items are typically classified as short term or long term. Short-term action items should be a teams immediate priority since these action items represent the complete mitigation for an incident. These action items will be monitored closely since delays can result in a repeat incident. Long-term action items are typically represented by larger projects or are changes with high levels of risk that need detailed implementation plans to mitigate implementation risks. Long-term action items are good candidates for Objectives and Key Results (OKRs) or quarterly goals since they may not be immediately actionable depending on the complexity of effort.

Remember that accidents and mistakes will happen. The goal of the incident management process is to catch problems early and reduce the potential impact of an incident. You and your teams will grow and become more efficient as you apply the incident management process for incidents. While an incident is an unfortunate event it does not mean we cannot improve from the lessons learned.

Conclusion
Hopefully this overview of the ThousandEyes incident management process has given you ideas for improving your own incident management processes. We covered:

Declaring, managing, and resolving an incident.
The postmortem process and continued improvements from lessons learned.
Using data-driven metrics to help determine if an incident needs to be declared.
Creating a strong response by empowering responders and delineating incident response roles.
Establish objective standards to classify incidents.
Develop and maintain clear guidelines to determine when an incident is reviewed, mitigated, and resolved.
Bring together responders and subject-matter experts to understand what happened and how to prevent similar issues in the future.
Implement platform and process improvements to prevent, detect, and reduce the impact of future incidents.
Incident Management
Incident
Thousandeyes
