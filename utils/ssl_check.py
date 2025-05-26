import ssl
import socket

def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])['organizationName']
                not_after = cert['notAfter']
                return f"Issuer: {issuer}, Expira em: {not_after}"
    except Exception as e:
        return f"Erro SSL: {e}"
