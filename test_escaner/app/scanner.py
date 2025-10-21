import scapy.all as scapy
import socket
import ipaddress

def obtener_red_local():
    """Detecta automáticamente el rango de red (ej. 192.168.0.0/24)."""
    try:
        # Obtiene la IP local
        hostname = socket.gethostname()
        ip_local = socket.gethostbyname(hostname)

        # Calcula la red /24 según la IP local
        ip_interface = ipaddress.ip_interface(f"{ip_local}/24")
        red = str(ip_interface.network)
        return red
    except Exception as e:
        print(f"[ERROR] No se pudo determinar la red local: {e}")
        # Valor por defecto si falla
        return "192.168.1.0/24"


def escanear_red(red=None):
    """Escanea la red local usando paquetes ARP y devuelve una lista de dispositivos activos."""
    try:
        if red is None:
            red = obtener_red_local()

        print(f"[INFO] Escaneando red: {red}")

        # Crea el paquete ARP
        arp_request = scapy.ARP(pdst=red)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        paquete = broadcast / arp_request

        # Envía el paquete y recibe las respuestas
        resultado = scapy.srp(paquete, timeout=2, verbose=0)[0]

        dispositivos = []
        for _, respuesta in resultado:
            try:
                host = socket.gethostbyaddr(respuesta.psrc)[0]
            except socket.herror:
                host = "Desconocido"
            dispositivos.append({
                "ip": respuesta.psrc,
                "mac": respuesta.hwsrc,
                "nombre": host
            })

        if not dispositivos:
            print("[ADVERTENCIA] No se detectaron dispositivos. Verifica permisos o firewall.")

        return dispositivos

    except PermissionError:
        print("[ERROR] Permiso denegado. Ejecuta como administrador.")
        return []
    except Exception as e:
        print(f"[ERROR] Fallo al escanear la red: {e}")
        return []
