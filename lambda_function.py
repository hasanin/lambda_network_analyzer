import dns.resolver
import re
import requests
import socket
from multiprocessing import Process, Pipe

"""
expected input:
{
    "ecr_endpoint": {
        "url": "https://domain1.com",
        "port": 443,
        },
    "another_endpoint": {
        "url": "domain2.com",
        "port": 80,
        }
}

########

expected output:
{
    'ecr_endpoint': {
        'url': 'https://domain1.com',
        'port': 443,
        'dns_state': True,
        'socket': [
            {'ip': '1.2.3.4', 'status': True},
            {'ip': '2.3.4.5', 'status': True}
            ],
        'l7_status': True,
        'ssl_validation': True
        },
    'repo_endpoint': {
        'url': 'website.com',
        'port': 80,
        'dns_state': True,
        'socket': [
            {'ip': '1.1.2.2', 'status': True},
            {'ip': '3.3.4.4', 'status': True}
            ],
        'l7_status': True,
        'ssl_validation': False
        }
}

"""


def extract_domain(url: str) -> str:
    domain_name = ""
    try:
        domain = re.search(
            r"^((http[s]?|ftp):\/)?\/?([^:\/\s]+)(:([^\/]*))?" r"((\/\w+)*\/)?([\w\-\.]+[^#?\s]+)?(\?([^#]*))?(#(.*))?$",
            url,
        )
        domain_name = domain.group(3)
    except Exception:
        raise Exception(f"Unable to derive domain name from {url}")
    finally:
        return domain_name


def get_dns(domain: str) -> list:
    ip_list = []
    try:
        record = dns.resolver.resolve(domain, "A")
        for ip in record:
            ip_list.append(str(ip))
    except Exception:
        pass
    finally:
        return ip_list


def check_socket(ip: str, port: int, conn):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        status = sock.connect_ex((ip, port))
    conn.send({"ip": str(ip), "status": True if status == 0 else False})
    conn.close


def socket_caller(ip_list: list, port: int) -> list:
    socket_status = []
    parent_connections = []
    processes = []
    for ip in ip_list:
        parent_conn, child_conn = Pipe()
        parent_connections.append(parent_conn)
        p = Process(target=check_socket, args=(ip, port, child_conn))
        processes.append(p)
        p.start()
    for p in processes:
        p.join()
    for parent_connection in parent_connections:
        socket_status.append(parent_connection.recv())
    return socket_status


def check_l7(url: str, port: int) -> bool:
    scheme = re.search(
        r"^((http[s]?|ftp):\/)?\/?([^:\/\s]+)(:([^\/]*))?" r"((\/\w+)*\/)?([\w\-\.]+[^#?\s]+)?(\?([^#]*))?(#(.*))?$",
        url,
    ).group(2)
    domain_name = extract_domain(url)
    if not scheme:
        scheme = "https"
    try:
        l7_status = requests.get(f"{scheme}://{domain_name}:{port}", timeout=2, verify=False).status_code in range(100, 499)
    except Exception:
        l7_status = False
    return l7_status


def check_ssl(url: str, port: int):
    scheme = re.search(
        r"^((http[s]?|ftp):\/)?\/?([^:\/\s]+)(:([^\/]*))?" r"((\/\w+)*\/)?([\w\-\.]+[^#?\s]+)?(\?([^#]*))?(#(.*))?$",
        url,
    ).group(2)
    domain_name = extract_domain(url)
    if scheme == "http":
        return None
    elif not scheme:
        scheme = "https"
    try:
        ssl_validation = requests.get(f"{scheme}://{domain_name}:{port}", timeout=2, verify=True).status_code in range(100, 499)
    except Exception:
        ssl_validation = False
    return ssl_validation


def check_endpoint(endpoint: dict, conn):
    result = endpoint
    domain_name = extract_domain(endpoint["url"])
    ip_list = get_dns(domain_name)
    if ip_list:
        result["dns_state"] = True
        result["socket"] = socket_caller(ip_list, endpoint["port"])
        result["l7_status"] = check_l7(endpoint["url"], endpoint["port"])
        result["ssl_validation"] = check_ssl(endpoint["url"], endpoint["port"])
    else:
        result["dns_state"] = False
        result["socket"] = []
        result["l7_status"] = None
        result["ssl_validation"] = None
    conn.send(result)
    conn.close


def output_generator(input: dict) -> dict:
    output = {}
    parent_connections = {}
    processes = []
    for endpoint, value in input.items():
        parent_conn, child_conn = Pipe()
        parent_connections[endpoint] = parent_conn
        p = Process(target=check_endpoint, args=(value, child_conn))
        processes.append(p)
    for p in processes:
        p.start()
    for p in processes:
        p.join()
    for endpoint in parent_connections:
        output[endpoint] = parent_connections[endpoint].recv()
    return output


def lambda_handler(event, context):
    return output_generator(event)
