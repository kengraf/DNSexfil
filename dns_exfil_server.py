#!/usr/bin/env python3
import argparse
import io
import re
import socketserver
import struct
import sys
import base64


PORT = 53
HEADER = '!HBBHHHH'
HEADER_SIZE = struct.calcsize(HEADER)

# Normally the name match pattern would be the following line
# DOMAIN_PATTERN = re.compile('^[A-Za-z0-9\-\.\_]+$')
# We only care about domain requests for our test domain
# 'RXhmaWwgaGVsbG8' is just URL64encoded 'Exfil Hello'
DOMAIN_PATTERN = re.compile('^RXhmaWwgaGVsbG8.fake$')

class DNSHandler(socketserver.BaseRequestHandler):

  def handle(self):
    socket = self.request[1]
    data = self.request[0]
    data_stream = io.BytesIO(data)

    # Read header
    (request_id, header_a, header_b, qd_count, an_count, ns_count, ar_count) = struct.unpack(HEADER, data_stream.read(HEADER_SIZE))

    # Read questions
    questions = []
    for i in range(qd_count):
      name_parts = []
      length = struct.unpack('B', data_stream.read(1))[0]
      while length != 0:
        name_parts.append(data_stream.read(length).decode('us-ascii'))
        length = struct.unpack('B', data_stream.read(1))[0]
      name = '.'.join(name_parts)

      if not DOMAIN_PATTERN.match(name):
        
        print('Invalid domain received: ' + name)
        # We are only responding to exfil requests
        return

      (qtype, qclass) = struct.unpack('!HH', data_stream.read(4))

      questions.append({'name': name, 'type': qtype, 'class': qclass})

    # Decode the sub_domain that is our exfil message
    exfil_hello = ''
    try:
      sub_domain = name.split('.')[0]
      # Fix URL based padding
      sub_domain += '=' * (4 - len(sub_domain) % 4)
      exfil_hello = base64.urlsafe_b64decode(sub_domain).decode('us-ascii')
    except:
      # Ignore any decoding errors
      return
    
    print('Exfil: ' + exfil_hello + ' from ' + str(self.client_address[0]) + ':' + str(self.client_address[1]))

    # Make response (note: we don't actually care about the questions, just return our canned response)
    response = io.BytesIO()

    # Header
    # Response, Authoriative
    response_header = struct.pack(HEADER, request_id, 0b10000100, 0b00000000, qd_count, 1, 0, 0)
    response.write(response_header)

    # Questions
    aaaa = False
    for q in questions:
      # Name
      for part in q['name'].split('.'):
        response.write(struct.pack('B', len(part)))
        response.write(part.encode('us-ascii'))
      response.write(b'\x00')

      # qtype, qclass
      aaaa = (q['type'] == 28)
      response.write(struct.pack('!HH', q['type'], q['class']))

    # The response is always a fake address
    response.write(b'\xc0\x0c') # Compressed name (pointer to question)
    if aaaa:
      response.write(struct.pack('!HH', 28, 1)) # type: AAAA, class: IN
      response.write(struct.pack('!I', 0)) # TTL: 0
      response.write(struct.pack('!H', 16)) # Record length
      response.write(bytearray([20,1,100,99,98,97,96,10,10,10,0,0,11,22,33,44])) # Fake IP6
    else:
      response.write(struct.pack('!HH', 1, 1)) # type: A, class: IN
      response.write(struct.pack('!I', 0)) # TTL: 0
      response.write(struct.pack('!H', 4)) # Record length
      response.write(bytearray([11,22,33,44])) # IP 11.22.33.44
    
    # Send response
    socket.sendto(response.getvalue(), self.client_address)

if __name__ == '__main__':
  server = socketserver.ThreadingUDPServer(('', PORT), DNSHandler)
  print('Running on port %d' % PORT)

  try:
    server.serve_forever()
  except KeyboardInterrupt:
    server.shutdown()
