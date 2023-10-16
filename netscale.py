import re
import requests
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress unverified HTTPS request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Function to configure the session to ignore SSL certificate errors
def configure_session_with_ssl_ignore():
    session = requests.Session()
    # Disable SSL certificate verification
    session.verify = False
    return session

def parseCookie(cookie):
    s = re.search(r'NSC_([a-zA-Z0-9\-\_\.]*)=([0-9a-f]+)', cookie)
    if s is not None:
        servicename = s.group(1)
        serverip_port = s.group(2)
        return servicename, serverip_port
    else:
        raise Exception('Could not parse cookie')

def decryptServiceName(servicename):
    trans = str.maketrans('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ','zabcdefghijklmnopqrstuvwxyZABCDEFGHIJKLMNOPQRSTUVWXY')
    realname = servicename.translate(trans)
    return realname

def decryptServerIPPort(serverip_port):
    # Take the second set of 8 characters as hex and XOR it with key 0x03081e11
    decoded_ip_port = int(serverip_port[8:16], 16) ^ 0x03081e11
    return decoded_ip_port

def decryptServerPort(serverip_port):
    # Take the last 4 characters as hex and XOR it with key 0x3630
    decoded_port = int(serverip_port[-4:], 16) ^ 0x3630
    return decoded_port

# Function to fetch and decrypt the NetScaler cookie
def fetch_and_decrypt_cookie(url):
    try:
        session = configure_session_with_ssl_ignore()
        response = session.get(url)
        if 'Set-Cookie' in response.headers:
            cookies = response.headers['Set-Cookie']
            netscaler_cookie = re.search(r'NSC_[\w\.\-]*=[\da-fA-F]+', cookies).group()
            servicename, serverip_port = parseCookie(netscaler_cookie)
            realname = decryptServiceName(servicename)
            decoded_ip_port = decryptServerIPPort(serverip_port)
            decoded_port = decryptServerPort(serverip_port)
            return realname, decoded_ip_port, decoded_port
        else:
            return None
    except Exception as e:
        print(f"Failed to fetch and decrypt the cookie from the URL: {e}")
        return None

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Fetch and decrypt NetScaler cookie from a URL's HTTP response.")
    parser.add_argument("--url", required=True, help="URL to fetch the cookie from")
    args = parser.parse_args()

    result = fetch_and_decrypt_cookie(args.url)

    if result:
        realname, decoded_ip, decoded_port = result
        print('vServer Name=%s' % realname)
        print('vServer IP=%d.%d.%d.%d' % ((decoded_ip >> 24) & 0xFF, (decoded_ip >> 16) & 0xFF, (decoded_ip >> 8) & 0xFF, decoded_ip & 0xFF))
        print('vServer Port=%s' % decoded_port)
    else:
        print("No valid NetScaler cookie found in the response.")
