from main import test_mtproxy, test_direct

# direct connection test
# By default we use test DC.
# To set which protocol we use:
# padded=True: use padded intermediate;
# intermediate=True: use intermediate;
# *left blank*: use abridged.
print(test_direct(intermediate=True))

# proxy connectivity test
# dc_id (2 = DC2, 10002 = test DC2, -2 = media CDN 2), proxy_ip, proxy_port, proxy_secret
# Transport protocol is chosen by the program depending on the `proxy_secret`.
print(test_mtproxy(2, '127.0.0.1', 443, 'ee380258ace24be50c6c3eac0571eb45676974756e65732e6170706c652e636f6d'))