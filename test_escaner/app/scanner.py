import socket
import ipaddress
import time
import subprocess
from scapy.all import ARP, Ether, srp, sr1, IP, ICMP


def obtener_ip_local():
    """Obtiene la IP local detectando la interfaz principal."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_local = s.getsockname()[0]
        s.close()
        return ip_local
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return None


def obtener_red_local(prefijo_default=24):
    """Calcula automáticamente la red local en formato CIDR."""
    ip_local = obtener_ip_local()
    if not ip_local:
        print("[ERROR] No se pudo obtener la IP local.")
        return None

    try:
        iface = ipaddress.ip_interface(f"{ip_local}/{prefijo_default}")
        return str(iface.network)
    except Exception as e:
        print(f"[WARN] No se pudo calcular la red: {e}")
        return None


def arp_scan(red_cidr=None, iface=None, timeout=3):
    """Escaneo ARP clásico (capa 2)."""
    if red_cidr is None:
        red_cidr = obtener_red_local()

    if not red_cidr:
        print("[ERROR] No hay red para escanear.")
        return []

    print(f"[INFO] ARP scan en {red_cidr}")

    try:
        arp_req = ARP(pdst=red_cidr)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        paquete = ether / arp_req

        respuestas = srp(paquete, timeout=timeout, verbose=0, iface=iface)[0]

        dispositivos = []
        for _, r in respuestas:
            try:
                nombre = socket.gethostbyaddr(r.psrc)[0]
            except Exception:
                nombre = "Desconocido"

            dispositivos.append({
                "ip": r.psrc,
                "mac": r.hwsrc,
                "nombre": nombre
            })

        return dispositivos

    except Exception as e:
        print(f"[ERROR] ARP FALLÓ: {e}")
        return []


def icmp_scan(red_cidr, timeout=1):
    """Escaneo ICMP (capa 3). Descubre hosts que no responden ARP."""
    try:
        red = ipaddress.ip_network(red_cidr, strict=False)
    except Exception as e:
        print(f"[ERROR] Red inválida para ICMP: {e}")
        return []

    print(f"[INFO] ICMP scan en {red_cidr}")
    dispositivos = []

    for ip in red.hosts():
        ip_str = str(ip)
        paquete = IP(dst=ip_str) / ICMP()

        try:
            respuesta = sr1(paquete, timeout=timeout, verbose=0)
            if respuesta:
                try:
                    nombre = socket.gethostbyaddr(ip_str)[0]
                except Exception:
                    nombre = "Desconocido"

                dispositivos.append({
                    "ip": ip_str,
                    "mac": None,
                    "nombre": nombre
                })
        except Exception:
            pass

    return dispositivos


def upnp_scan(timeout=2):
    """Escaneo SSDP/UPnP para descubrir dispositivos IoT y Smart TVs."""
    ssdp_request = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    )

    dispositivos = []

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    try:
        sock.sendto(ssdp_request.encode(), ("239.255.255.250", 1900))
    except Exception as e:
        print(f"[WARN] No se pudo enviar SSDP: {e}")
        return dispositivos

    inicio = time.time()

    while time.time() - inicio < timeout:
        try:
            data, addr = sock.recvfrom(1024)
            dispositivos.append({
                "ip": addr[0],
                "mac": None,
                "nombre": "UPnP/SSDP device"
            })
        except socket.timeout:
            break
        except Exception:
            break

    return dispositivos


def mdns_scan(timeout=2):
    """Escanea dispositivos que responden a mDNS (iPhone, Chromecast, IoT)."""
    MCAST_GRP = "224.0.0.251"
    MCAST_PORT = 5353

    mensaje = b"\x00" * 12  
    dispositivos = []

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        sock.sendto(mensaje, (MCAST_GRP, MCAST_PORT))
    except Exception as e:
        print(f"[WARN] No se pudo enviar mDNS: {e}")
        return dispositivos

    try:
        while True:
            data, addr = sock.recvfrom(2048)
            dispositivos.append({
                "ip": addr[0],
                "mac": None,
                "nombre": "mDNS device"
            })
    except socket.timeout:
        pass
    except Exception:
        pass

    return dispositivos


def netbios_scan(red_cidr):
    """Escaneo NetBIOS Name Service."""
    try:
        red = ipaddress.ip_network(red_cidr, strict=False)
    except Exception:
        return []

    dispositivos = []

    for ip in red.hosts():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.3)

        mensaje = b"\x80" + b"\x00" * 49  # Consulta NBNS estándar

        try:
            sock.sendto(mensaje, (str(ip), 137))
            data, addr = sock.recvfrom(1024)

            dispositivos.append({
                "ip": addr[0],
                "mac": None,
                "nombre": "NetBIOS device"
            })

        except Exception:
            pass

    return dispositivos


def analizar_dispositivo(ip):
    """Análisis simple de latencia y puertos abiertos para estimar riesgo."""
    analisis = {}

    
    try:
        salida = subprocess.check_output(f"ping -n 1 {ip}", shell=True).decode("latin1")
        if "Tiempo=" in salida or "time=" in salida:
            if "Tiempo=" in salida:
                parte = salida.split("Tiempo=")[1]
            else:
                parte = salida.split("time=")[1]
            num = "".join(ch for ch in parte if ch.isdigit())
            analisis["latencia_ms"] = int(num) if num else None
        else:
            analisis["latencia_ms"] = None
    except Exception:
        analisis["latencia_ms"] = None

    
    puertos = [22, 80, 443, 8080]
    abiertos = []
    for p in puertos:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        try:
            if sock.connect_ex((ip, p)) == 0:
                abiertos.append(p)
        except Exception:
            pass
        finally:
            sock.close()

    analisis["puertos_abiertos"] = abiertos

    
    if 22 in abiertos:
        analisis["riesgo"] = "Alto"
    elif any(p in abiertos for p in (80, 8080)):
        analisis["riesgo"] = "Medio"
    else:
        analisis["riesgo"] = "Bajo"

    return analisis


def escanear_red():
    """Escaneo híbrido ARP + ICMP + UPnP + mDNS + NetBIOS con análisis básico."""
    red = obtener_red_local()
    if not red:
        return []

    print(f"[INFO] Escaneando red: {red}")

    arp = arp_scan(red)
    icmp = icmp_scan(red, timeout=0.5)
    upnp = upnp_scan()
    mdns = mdns_scan()
    nb = netbios_scan(red)

    print(f"[INFO] ARP detectó {len(arp)} dispositivos")
    print(f"[INFO] ICMP detectó {len(icmp)} dispositivos")
    print(f"[INFO] UPnP detectó {len(upnp)} dispositivos")
    print(f"[INFO] mDNS detectó {len(mdns)} dispositivos")
    print(f"[INFO] NetBIOS detectó {len(nb)} dispositivos")

    mapa = {}

    for lista in (arp, icmp, upnp, mdns, nb):
        for d in lista:
            ip = d.get("ip")
            if not ip:
                continue
            if ip not in mapa:
                mapa[ip] = d

    dispositivos = []
    for ip, d in mapa.items():
        analisis = analizar_dispositivo(ip)
        d.update(analisis)
        d["estado"] = "Inseguro" if analisis.get("riesgo") == "Alto" else "Activo"
        dispositivos.append(d)

    print(f"[INFO] Total final detectado: {len(dispositivos)}")
    return dispositivos


if __name__ == "__main__":
    dispositivos = escanear_red()
    for d in dispositivos:
        print(d)
