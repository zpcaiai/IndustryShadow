# Safety-policy violation

Immediately disable the implicated service identity and scale the action executor to
zero. Preserve audit, request, approval, plan, simulator identity, snapshots, and
NetworkPolicy logs. Any real-endpoint write/call attempt is a release red line: do not
resume promotion or certification until the incident is contained, root-caused,
regression-tested, and independently reviewed.
