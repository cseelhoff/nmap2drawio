from ldap3 import Server, Connection

server_uri = 'ldap://localhost:3890'
search_base = 'dc=example,dc=org'
search_filter = '(uid=abcd)'
attrs = ['*']

server = Server(server_uri)
with Connection(server, auto_bind=True) as conn:
    conn.search(search_base, search_filter, attributes=attrs)
    print(conn.entries)
