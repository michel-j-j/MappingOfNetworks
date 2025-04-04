import socket
import nmap
import dearpygui.dearpygui as dpg
import threading

dpg.create_context()

# Global variables
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
    octets = ip.split('.')
    network_ip = '.'.join(octets[:3] + ['0'])
    return f"{network_ip}/{cidr}"


def generate_recommendations():
    recommendations = []

    # Common port detection
    common_ports = {
        21: "[FTP] Consider disabling FTP and use SFTP/FTPS",
        22: "[SSH] Ensure key-based authentication and change default port",
        80: "[HTTP] Configure firewall and use HTTPS",
        443: "[HTTPS] Verify SSL certificate is updated",
        3389: "[RDP] Never expose this port directly to the Internet"
    }

    # Generate recommendations based on open ports
    for port in open_ports:
        if port in common_ports:
            recommendations.append(f"• {common_ports[port]}")

    # General recommendations
    general_recommendations = [
        "• [Security] Change default device passwords",
        "• [Update] Regularly update router firmware",
        "• [Network] Segment your network for IoT devices",
        "• [Wi-Fi] Use WPA2/WPA3 encryption",
        "• [Configuration] Disable UPnP if not strictly needed"
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
        _log(f"Starting network scan: {network}...")

        # Host discovery
        nm.scan(hosts=network, arguments='-sn')
        hosts_list = nm.all_hosts()

        if not hosts_list:
            _log("No hosts found in the network")
            return

        for host in hosts_list:
            if stop_scan:
                break

            current_hosts.append(host)
            _log(f"\nScanning host: {host}")

            # Port scanning
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
                _log(f"Error scanning host {host}: {str(e)}")

    except Exception as e:
        _log(f"General error: {str(e)}")
    finally:
        scanning = False
        _log("\nScan completed")
        dpg.enable_item("start_btn")
        dpg.disable_item("stop_btn")
        _update_gui()


def _update_gui():
    # Update main results
    dpg.delete_item("results_tree", children_only=True)

    for host, info in scan_results.items():
        with dpg.tree_node(label=f"{host} ({info['hostname']})", parent="results_tree"):
            dpg.add_text(f"State: {info['state']}")
            with dpg.tree_node(label="Detected Ports"):
                for port, state in info['ports']:
                    dpg.add_text(f"Port {port}: {state}")

    # Update open ports list
    dpg.delete_item("open_ports_list", children_only=True)
    for port in sorted(open_ports):
        dpg.add_text(f"• Port {port} open", parent="open_ports_list")

    # Update recommendations
    dpg.delete_item("recommendations_list", children_only=True)
    for recommendation in generate_recommendations():
        dpg.add_text(recommendation, parent="recommendations_list")


def start_scan_callback():
    global stop_scan
    stop_scan = False

    # Clear previous results
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
    # Configuration section
    with dpg.group(horizontal=True):
        dpg.add_input_text(label="Local IP", default_value=get_local_ip(), readonly=True, width=150)
        dpg.add_input_text(label="Network", tag="network_input",
                           default_value=construct_network_range(get_local_ip()), width=200)
        dpg.add_button(label="Refresh IP",
                       callback=lambda: dpg.set_value("network_input", construct_network_range(get_local_ip())))

    # Control buttons
    with dpg.group(horizontal=True):
        dpg.add_button(label="Start Scan", tag="start_btn", callback=start_scan_callback)
        dpg.add_button(label="Stop Scan", tag="stop_btn", show=False, callback=stop_scan_callback)

    # Scan results
    dpg.add_text("Scan Results:")
    dpg.add_tree_node(tag="results_tree")

    # Open ports section
    dpg.add_separator()
    with dpg.collapsing_header(label="Detected Open Ports", default_open=True):
        with dpg.child_window(height=100, tag="open_ports_list"):
            pass

    # Recommendations tab
    dpg.add_separator()
    with dpg.collapsing_header(label="Security Recommendations", default_open=True):
        with dpg.child_window(height=200, tag="recommendations_list"):
            dpg.add_text("Run a scan to get recommendations", tag="placeholder_text")

    # Activity log
    dpg.add_separator()
    dpg.add_text("Activity Log:")
    with dpg.child_window(height=200, tag="log_window"):
        pass

dpg.create_viewport(title='Network Analyzer', width=1000, height=800)
dpg.setup_dearpygui()
dpg.show_viewport()
dpg.set_primary_window("MainWindow", True)

# Check nmap installation
try:
    nm = nmap.PortScanner()
except:
    with dpg.window(label="Error", modal=True, show=True):
        dpg.add_text("Error: nmap is not installed or could not be found.")
        dpg.add_button(label="Close", callback=lambda: dpg.stop_dearpygui())

dpg.start_dearpygui()
dpg.destroy_context()