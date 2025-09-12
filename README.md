I worked on 3 projects:
1) Traceroute: 
Part A: I implemented traceroute using the provided sendsock and recvsock to send UDP probes and receive ICMP responses. For each TTL, I sent multiple probes, parsed IPv4/ICMP/UDP headers to extract key fields, and recorded routers as a list of lists. I printed results at each hop and stopped once the destination replied.

Part B: handle cases of irrelevant packets, e.g. ICMP messages with the wrong type/code, truncated headers, or unrelated payloads. I also dealt with delayed responses: if a response for TTL=4 arrived after I had moved on to TTL=5, I still recognized it as belonging to the earlier probe and avoided mis-assigning it. I supported silent routers and packet loss by returning an empty sublist when no router responded at a given TTL. 