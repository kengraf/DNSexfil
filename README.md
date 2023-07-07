# DNSexfil
Simple hello exchange to start DNS based exfil

This repo supports teaching how DNS can be used to exfilrate information.  The "hello" returns the IP address the client would connect with.  It is a student effort to modify the server to handle a proper exfilration.

dns_exfil_server.py as is responses only to requests for 'RXhmaWwgaGVsbG8.fake'. Returing fake IP4 and IP6 addresses.  'RXhmaWwgaGVsbG8' is just 'Exfil hello' base64 urlencoded.  

dns_exfil_client.py as is just says hello.  A real world client would shift to a second level after hello.

Student discussion  
- How much data can be sent in a single DNS query?
- How would the affected site discover the exfilration?
- Should the client after the hello exchange shift to HTTPS?
- Would a DNS server discover the exfilration?
- Would a network firewall discover the exfilration?
- Would a DLP solution discover the exfilration?
- What happens to the exfilration if a UDP packet fails?
- Is adding encryption needed?
- How would you add encryption?
