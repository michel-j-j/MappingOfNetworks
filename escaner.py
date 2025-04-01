import socket
import nmap


def get_local_ip():
    """
    Obtiene la IP local conectándose a un servidor remoto para evitar obtener 127.0.0.1.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return local_ip


def construct_network_range(ip, cidr=24):
    """
    Construye el rango de red asumiendo una máscara /24.
    Ej.: 192.168.1.10 -> 192.168.1.0/24
    """
    octetos = ip.split('.')
    network_ip = '.'.join(octetos[:3] + ['0'])
    return f"{network_ip}/{cidr}"


def scan_network(network):
    nm = nmap.PortScanner()

    print(f"Escaneando la red {network}...")
    # Escaneo de dispositivos conectados (ping scan)
    nm.scan(hosts=network, arguments='-sn')

    hosts_list = nm.all_hosts()
    if not hosts_list:
        print("No se detectaron hosts en la red.")
        return

    for host in hosts_list:
        # Verificar si hay información detallada para el host
        if host not in nm._scan_result.get("scan", {}):
            print(f"\nHost: {host} (Información no disponible)")
            continue

        try:
            host_info = nm[host]
            hostname = host_info.hostname() or "N/A"
            state = host_info.state() or "N/A"
        except KeyError:
            print(f"\nHost: {host} (Información no disponible)")
            continue

        print(f"\nHost: {host} ({hostname})")
        print(f"Estado: {state}")

        # Realizar un escaneo de puertos usando TCP connect scan (-sT)
        print("Escaneando puertos comunes...")
        try:
            nm.scan(host, arguments='-sT -Pn -T4')
        except Exception as e:
            print(f"Error al escanear el host {host}: {e}")
            continue

        # Mostrar resultados del escaneo de puertos
        try:
            for proto in nm[host].all_protocols():
                print(f"Protocolo: {proto}")
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    port_state = nm[host][proto][port]['state']
                    print(f"  Puerto {port}: {port_state}")
        except KeyError:
            print(f"No se encontraron detalles de puertos para el host {host}")


if __name__ == "__main__":
    local_ip = get_local_ip()
    print(f"IP local detectada: {local_ip}")

    # Construir el rango de red asumiendo una máscara /24
    network_range = construct_network_range(local_ip, cidr=24)
    print(f"Rango de red a escanear: {network_range}")

    scan_network(network_range)
