import socket
import nmap
import dearpygui.dearpygui as dpg
import threading

dpg.create_context()

# Variables globales
scanning = False
stop_scan = False
scan_results = {}
current_hosts = []
open_ports = set()


def _log(message):
    dpg.add_text(message, parent="log_window")


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def construct_network_range(ip, cidr=24):
    octetos = ip.split('.')
    network_ip = '.'.join(octetos[:3] + ['0'])
    return f"{network_ip}/{cidr}"


def generate_recommendations():
    recommendations = []

    # Detección de puertos comunes (iconos reemplazados por texto)
    common_ports = {
        21: "[FTP] Considera deshabilitar FTP y usar SFTP/FTPS",
        22: "[SSH] Asegúrate de usar autenticación por clave y cambia el puerto predeterminado",
        80: "[HTTP] Configura un firewall y usa HTTPS",
        443: "[HTTPS] Verifica que tu certificado SSL esté actualizado",
        3389: "[RDP] Nunca expongas este puerto a Internet directamente"
    }

    # Generar recomendaciones basadas en puertos abiertos
    for port in open_ports:
        if port in common_ports:
            recommendations.append(f"• {common_ports[port]}")

    # Recomendaciones generales
    general_recommendations = [
        "• [Seguridad] Cambia las contraseñas predeterminadas de tus dispositivos",
        "• [Actualización] Actualiza el firmware de tu router regularmente",
        "• [Red] Separa tu red en subredes para dispositivos IoT",
        "• [Wi-Fi] Usa cifrado WPA2/WPA3 en tu red inalámbrica",
        "• [Configuración] Deshabilita UPnP si no es estrictamente necesario"
    ]

    return recommendations + general_recommendations


def scan_network(network):
    global scanning, stop_scan, scan_results, current_hosts, open_ports

    scanning = True
    stop_scan = False
    scan_results = {}
    current_hosts = []
    open_ports = set()

    try:
        nm = nmap.PortScanner()
        _log(f"Iniciando escaneo de red: {network}...")

        # Escaneo de hosts
        nm.scan(hosts=network, arguments='-sn')
        hosts_list = nm.all_hosts()

        if not hosts_list:
            _log("No se encontraron hosts en la red")
            return

        for host in hosts_list:
            if stop_scan:
                break

            current_hosts.append(host)
            _log(f"\nEscaneando host: {host}")

            # Escaneo de puertos
            try:
                nm.scan(host, arguments='-sT -Pn -T4')

                host_info = {
                    'hostname': nm[host].hostname() or "N/A",
                    'state': nm[host].state(),
                    'ports': []
                }

                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        state = nm[host][proto][port]['state']
                        if state == 'open':
                            open_ports.add(port)
                        host_info['ports'].append((port, state))

                scan_results[host] = host_info
                _update_gui()

            except Exception as e:
                _log(f"Error en host {host}: {str(e)}")

    except Exception as e:
        _log(f"Error general: {str(e)}")
    finally:
        scanning = False
        _log("\nEscaneo completado")
        dpg.enable_item("start_btn")
        dpg.disable_item("stop_btn")
        _update_gui()


def _update_gui():
    # Actualizar resultados principales
    dpg.delete_item("results_tree", children_only=True)

    for host, info in scan_results.items():
        with dpg.tree_node(label=f"{host} ({info['hostname']})", parent="results_tree"):
            dpg.add_text(f"Estado: {info['state']}")
            with dpg.tree_node(label="Puertos detectados"):
                for port, state in info['ports']:
                    dpg.add_text(f"Puerto {port}: {state}")

    # Actualizar lista de puertos abiertos
    dpg.delete_item("open_ports_list", children_only=True)
    for port in sorted(open_ports):
        dpg.add_text(f"• Puerto {port} abierto", parent="open_ports_list")

    # Actualizar recomendaciones
    dpg.delete_item("recommendations_list", children_only=True)
    for recommendation in generate_recommendations():
        dpg.add_text(recommendation, parent="recommendations_list")


def start_scan_callback():
    global stop_scan
    stop_scan = False

    # Limpiar resultados anteriores
    scan_results.clear()
    current_hosts.clear()
    open_ports.clear()
    dpg.delete_item("log_window", children_only=True)
    dpg.delete_item("results_tree", children_only=True)
    dpg.delete_item("open_ports_list", children_only=True)
    dpg.delete_item("recommendations_list", children_only=True)

    network = dpg.get_value("network_input")
    thread = threading.Thread(target=scan_network, args=(network,))
    thread.start()

    dpg.disable_item("start_btn")
    dpg.enable_item("stop_btn")


def stop_scan_callback():
    global stop_scan
    stop_scan = True
    dpg.enable_item("start_btn")
    dpg.disable_item("stop_btn")


with dpg.window(tag="MainWindow"):
    # Sección de configuración
    with dpg.group(horizontal=True):
        dpg.add_input_text(label="IP Local", default_value=get_local_ip(), readonly=True, width=150)
        dpg.add_input_text(label="Red", tag="network_input",
                           default_value=construct_network_range(get_local_ip()), width=200)
        dpg.add_button(label="Recargar IP",
                       callback=lambda: dpg.set_value("network_input", construct_network_range(get_local_ip())))

    # Botones de control
    with dpg.group(horizontal=True):
        dpg.add_button(label="Iniciar Escaneo", tag="start_btn", callback=start_scan_callback)
        dpg.add_button(label="Detener Escaneo", tag="stop_btn", show=False, callback=stop_scan_callback)

    # Resultados del escaneo
    dpg.add_text("Resultados del escaneo:")
    dpg.add_tree_node(tag="results_tree")

    # Sección de puertos abiertos
    dpg.add_separator()
    with dpg.collapsing_header(label="Puertos Abiertos Detectados", default_open=True):
        with dpg.child_window(height=100, tag="open_ports_list"):
            pass

    # Pestaña de recomendaciones
    dpg.add_separator()
    with dpg.collapsing_header(label="Recomendaciones de Seguridad", default_open=True):
        with dpg.child_window(height=200, tag="recommendations_list"):
            dpg.add_text("Ejecuta un escaneo para obtener recomendaciones", tag="placeholder_text")

    # Log de actividad
    dpg.add_separator()
    dpg.add_text("Registro de actividad:")
    with dpg.child_window(height=200, tag="log_window"):
        pass

dpg.create_viewport(title='Analizador de Red', width=1000, height=800)
dpg.setup_dearpygui()
dpg.show_viewport()
dpg.set_primary_window("MainWindow", True)

# Verificar si nmap está instalado
try:
    nm = nmap.PortScanner()
except:
    with dpg.window(label="Error", modal=True, show=True):
        dpg.add_text("Error: nmap no está instalado o no se pudo encontrar.")
        dpg.add_button(label="Cerrar", callback=lambda: dpg.stop_dearpygui())

dpg.start_dearpygui()
dpg.destroy_context()