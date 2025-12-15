import socket
import ipaddress
import time
import select
import subprocess
from scapy.all import ARP, Ether, IP, ICMP, sr1, srp, TCP
from datetime import datetime, timedelta

PUERTOS_CRITICOS = {23, 2323, 7547, 445, 21, 3389}  

def clasificar_dispositivo(ip_info, dispositivo_actual=None):

    ahora = datetime.utcnow()

    if dispositivo_actual is None or dispositivo_actual.fecha_ultima_visto is None:
        return "nuevo"

    if dispositivo_actual.fecha_ultima_visto > ahora - timedelta(days=1):
        puertos = set(ip_info.get("puertos_abiertos", []))
        if puertos & PUERTOS_CRITICOS:
            return "sospechoso"
        return "nuevo"

    puertos = set(ip_info.get("puertos_abiertos", []))
    if puertos & PUERTOS_CRITICOS:
        return "sospechoso"
    nombre = (ip_info.get("nombre") or "").lower()
    tipo = (ip_info.get("tipo") or "").lower()

    if not nombre and not tipo:
        return "nuevo"

    return "seguro"

def obtener_ip_local():
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

def inferir_tipo_por_nombre(nombre: str) -> str:
    n = (nombre or "").lower()

    if any(x in n for x in ["cam", "camera", "cámara"]):
        return "Cámara"
    if "tv" in n or "smarttv" in n or "smart tv" in n:
        return "Televisión"
    if any(x in n for x in ["iphone", "android", "galaxy", "phone"]):
        return "Smartphone"
    if "tablet" in n or "ipad" in n:
        return "Tableta"
    if any(x in n for x in ["router", "gateway", "modem", "gw"]):
        return "Router"
    if any(x in n for x in ["printer", "impresora", "hp ", "epson", "canon"]):
        return "Impresora"
    if any(x in n for x in ["desktop", "laptop", "notebook", "pc"]):
        return "Computadora"
    return "Desconocido"

def arp_scan(red_cidr, timeout=1, iface=None, max_hosts=256):
    try:
        red = ipaddress.ip_network(red_cidr, strict=False)
    except Exception as e:
        print(f"[ERROR] Red inválida para ARP: {e}")
        return []

    print(f"[INFO] ARP scan en {red_cidr}")

    hosts = list(red.hosts())[:max_hosts]
    if not hosts:
        return []

    rango = f"{red.network_address}/{red.prefixlen}"
    paquete = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=rango)

    ans, _ = srp(paquete, timeout=timeout, iface=iface, verbose=0)

    dispositivos = []
    vistos = set()  

    for _, resp in ans:
        ip = resp[ARP].psrc
        mac = resp[Ether].src

        if ip in vistos:
            continue
        vistos.add(ip)

        try:
            nombre = socket.gethostbyaddr(ip)[0]
        except Exception:
            nombre = "Desconocido"

        tipo = inferir_tipo_por_nombre(nombre)

        dispositivos.append({
            "ip": ip,
            "mac": mac,
            "nombre": nombre,
            "tipo": tipo,
            "origen": "ARP"
        })

    return dispositivos

def icmp_scan(red_cidr, timeout=0.5, max_duration=30, iface=None):
    try:
        red = ipaddress.ip_network(red_cidr, strict=False)
    except Exception as e:
        print(f"[ERROR] Red inválida para ICMP: {e}")
        return []

    print(f"[INFO] ICMP scan en {red_cidr}")
    dispositivos = []

    inicio_scan = time.time()  

    for ip in red.hosts():        
        if time.time() - inicio_scan > max_duration:
            print(f"[INFO] Tiempo máximo de {max_duration}s para ICMP alcanzado. "
                  f"Pasando al siguiente proceso.")
            break

        ip_str = str(ip)
        paquete = IP(dst=ip_str) / ICMP()

        try:
            
            respuesta = sr1(paquete, timeout=timeout, verbose=0)
            if not respuesta:
                continue

            try:
                nombre = socket.gethostbyaddr(ip_str)[0]
            except Exception:
                nombre = "Desconocido"

            mac = obtener_mac_por_arp(ip_str, timeout=0.7, iface=iface)

            puertos_abiertos = escanear_puertos_basico(ip_str, timeout=0.3)
            tipo = inferir_tipo_por_puertos(puertos_abiertos)  

            dispositivos.append({
                "ip": ip_str,
                "mac": mac,
                "nombre": nombre,
                "tipo": tipo,
                "puertos": puertos_abiertos,
                "origen": "ICMP"
            })
        
        except Exception:
            
            continue


    return dispositivos

def obtener_mac_por_arp(ip, timeout=1, iface=None):
    try:
        paquete = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(paquete, timeout=timeout, iface=iface, verbose=0)
        for _, respuesta in ans:
            return respuesta[Ether].src
    except Exception:
        pass
    return None

def inferir_tipo_por_upnp(server: str, st: str) -> str:
    s = (server or "").lower()
    t = (st or "").lower()

    if "tv" in s or "tv" in t:
        return "Televisión"
    if any(x in s for x in ["camera", "cam"]) or "ipcamera" in t:
        return "Cámara IP"
    if "router" in s or "gateway" in s or "dsl" in s:
        return "Router"
    if any(x in s for x in ["printer", "impresora", "hp ", "epson", "canon"]):
        return "Impresora"
    if "chromecast" in s or "cast" in s:
        return "Reproductor multimedia"
    if "sonos" in s or "speaker" in s:
        return "Altavoz inteligente"
    return "Dispositivo IoT"

def upnp_scan(timeout=3):
    print("[INFO] UPnP/SSDP scan")

    dispositivos = {}
    mensaje = "\r\n".join([
        'M-SEARCH * HTTP/1.1',
        'HOST: 239.255.255.250:1900',
        'MAN: "ssdp:discover"',
        'MX: 2',
        'ST: ssdp:all',
        '', ''
    ]).encode("utf-8")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    sock.sendto(mensaje, ("239.255.255.250", 1900))

    fin = time.time() + timeout

    try:
        while time.time() < fin:
            ready, _, _ = select.select([sock], [], [], fin - time.time())
            if not ready:
                break

            data, addr = sock.recvfrom(2048)
            ip = addr[0]

            texto = data.decode(errors="ignore")
            server = None
            st = None
            usn = None

            for line in texto.split("\r\n"):
                if not line:
                    continue
                lower = line.lower()
                if lower.startswith("server:"):
                    server = line.split(":", 1)[1].strip()
                elif lower.startswith("st:"):
                    st = line.split(":", 1)[1].strip()
                elif lower.startswith("usn:"):
                    usn = line.split(":", 1)[1].strip()

            if server and usn:
                nombre = f"{server} ({usn})"
            elif server:
                nombre = server
            elif usn:
                nombre = usn
            else:
                nombre = "UPnP/SSDP device"

            tipo = inferir_tipo_por_upnp(server, st)

            if ip in dispositivos:
                dev = dispositivos[ip]
                if dev["nombre"] == "UPnP/SSDP device" and nombre:
                    dev["nombre"] = nombre
                if dev["tipo"] == "Dispositivo IoT" and tipo != "Dispositivo IoT":
                    dev["tipo"] = tipo
            else:
                dispositivos[ip] = {
                    "ip": ip,
                    "mac": None,           
                    "nombre": nombre,
                    "tipo": tipo,
                    "origen": "UPnP",
                }

    except Exception as e:
        print(f"[WARN] Error en UPnP scan: {e}")
    finally:
        sock.close()

    return list(dispositivos.values())

PUERTOS_COMUNES = [80, 443, 554, 8008, 8080, 23, 22, 445, 9100]

def escanear_puertos_basico(ip, timeout=0.4):
    abiertos = []
    for port in PUERTOS_COMUNES:
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp and resp.haslayer(TCP):
            flags = resp[TCP].flags
            
            if flags & 0x12 == 0x12:
                abiertos.append(port)
    return abiertos

def inferir_tipo_por_puertos(open_ports):
    if 9100 in open_ports:
        return "Impresora"
    if 554 in open_ports:
        return "Cámara IP"
    if 445 in open_ports:
        return "PC / Servidor (SMB)"
    if 23 in open_ports:
        return "Router / Dispositivo de red"
    if 80 in open_ports or 443 in open_ports:
        return "Dispositivo con panel web"
    return "Desconocido"

def mdns_scan(timeout=2):
    
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
    try:
        red = ipaddress.ip_network(red_cidr, strict=False)
    except Exception:
        return []

    dispositivos = []

    for ip in red.hosts():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.3)

        mensaje = b"\x80" + b"\x00" * 49  

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
    red = obtener_red_local()
    if not red:
        return []

    print(f"[INFO] Escaneando red: {red}")

    arp = arp_scan(red)
    icmp = icmp_scan(red, timeout=0.5, max_duration=30)
    upnp = upnp_scan()
    mdns = mdns_scan()
    nb = netbios_scan(red)

    dispositivos = fusionar_por_ip(arp, icmp, upnp, mdns, nb)

    print(f"[INFO] Dispositivos fusionados: {len(dispositivos)}")

    return dispositivos

if __name__ == "__main__":
    dispositivos = escanear_red()
    for d in dispositivos:
        print(d)

def fusionar_por_ip(*listas):
    fusion = {}

    def mejor_nombre(actual, nuevo):
        if not actual or actual == "Desconocido":
            return nuevo
        if nuevo and nuevo != "Desconocido" and len(nuevo) > len(actual):
            return nuevo
        return actual

    def mejor_tipo(actual, nuevo):
        if not actual or actual == "Desconocido":
            return nuevo
        if nuevo and nuevo != "Desconocido" and len(nuevo) > len(actual):
            return nuevo
        return actual

    for lista in listas:
        if not lista:
            continue

        for d in lista:
            ip = d.get("ip")
            if not ip:
                continue

            if ip not in fusion:
                fusion[ip] = {
                    "ip": ip,
                    "mac": d.get("mac"),
                    "nombre": d.get("nombre") or "Desconocido",
                    "tipo": d.get("tipo") or "Desconocido",
                    "puertos": d.get("puertos") or [],
                    "origenes": [d.get("origen", "desconocido")],
                }
                continue

            f = fusion[ip]

            if not f["mac"] and d.get("mac"):
                f["mac"] = d["mac"]

            f["nombre"] = mejor_nombre(f["nombre"], d.get("nombre"))

            f["tipo"] = mejor_tipo(f["tipo"], d.get("tipo"))

            if d.get("puertos"):
                for p in d["puertos"]:
                    if p not in f["puertos"]:
                        f["puertos"].append(p)

            nuevo_origen = d.get("origen", "desconocido")
            if nuevo_origen not in f["origenes"]:
                f["origenes"].append(nuevo_origen)

    return list(fusion.values())
