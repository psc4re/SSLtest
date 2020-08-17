from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna, sys
from socket import socket
# Script to find CA names.  
#Author - psc4re
#Input file FQDNs seperated per line
#Usage ./SSLCA.py <<inputfile.txt>> <<outputfile.csv>>
port = 443
def get_ca(hostname):
    exists = 1
    try:
        hostname_idna = idna.encode(hostname)
        sock = socket()
        sock.connect((hostname, port))
        #peername = sock.getpeername()
        ctx = SSL.Context(SSL.TLSv1_2_METHOD)
        ctx.check_hostname = False
        ctx.verify_mode = SSL.VERIFY_NONE
        sock_ssl = SSL.Connection(ctx,sock)
        sock_ssl.set_connect_state()
        sock_ssl.set_tlsext_host_name(hostname_idna)
        sock_ssl.do_handshake()
        cert = sock_ssl.get_peer_certificate()
        crypto_cert = cert.to_cryptography()
        sock_ssl.close()
        sock.close()
        exists = 1
    except:
        exists = 0 
    if exists == 1:
        try:
            names = crypto_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            print(hostname+" , "+names[0].value)
            return hostname+" , "+names[0].value
        except x509.ExtensionNotFound:
            print(hostname+ ", Failed")
            return hostname+ ", Failed"
    else:
        print(hostname+ ", Failed")
        return hostname+ ", Failed"

if __name__ == '__main__':
    inputfile = sys.argv[1]
    outputfile = sys.argv[2]
    with open(inputfile) as f:
        hosts = f.readlines()
        f2 = open(outputfile, "w+")
        for hostnames in hosts:
            data = get_ca(hostnames.strip())
            f2.write(str(data)+"\n")
        f2.close()
