from ldap3 import Server, Connection
import dns.resolver

# LDAP enumeration
server_uri = 'ldap://localhost:3890'
search_base = 'dc=example,dc=org'
search_filter = '(objectclass=*)'  # This filter will return all entries
attrs = ['*']

server = Server(server_uri)
with Connection(server, auto_bind=True) as conn:
    conn.search(search_base, search_filter, attributes=attrs)
    print("LDAP Entries:")
    for entry in conn.entries:
        print(entry)

# DNS enumeration
resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8']  # Google's DNS server
domain = 'example.com'

print("\nDNS Entries:")
for rdata in resolver.resolve(domain, 'A'):
    print('Host', domain, 'has IP', rdata)