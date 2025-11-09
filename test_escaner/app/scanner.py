import socket
import ipaddress
from scapy.all import ARP, Ether, srp, sr1, IP, ICMP, conf

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
        print("[ERROR] No se pudo determinar la IP local.")
        return None
    try:
        iface_net = ipaddress.ip_interface(f"{ip_local}/{prefijo_default}")
        return str(iface_net.network)
    except Exception as e:
        print(f"[WARN] No se pudo calcular la red automaticamente: {e}")
        return None
    
def arp_scan(red_cidr=None, iface=None, timeout=3):

    if red_cidr is None:
        red_cidr = obtener_red_local()
    if not red_cidr:
        print("[ERROR] No hay red para escanear.")
        return []
    
    print(f"[INFO] ARP scan en {red_cidr} (iface={iface})")
    try:
        arp_req = ARP(pdst=red_cidr)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        paquete = ether / arp_req

        ans = srp(paquete, timeout=timeout, verbose=0, iface=iface)[0]

        dispositivos = []
        for _, r in ans:
            try:
                host = socket.gethostbyaddr(r.psrc)[0]
            except socket.herror:
                host = "Desconocido"
            dispositivos.append({"ip": r.psrc, "mac": r.hwsrc, "nombre": host})
        return dispositivos

    except RuntimeError as e:
        
        print(f"[ERROR] ARP scan falló: {e}")
        print("[INFO] Intentando escaneo ICMP (fallback L3).")
        return icmp_scan(red_cidr, timeout=timeout)

    except Exception as e:
        print(f"[ERROR] Fallo ARP scan: {e}")
        return []

def icmp_scan(red_cidr, timeout=1):
    
    try:
        net = ipaddress.ip_network(red_cidr, strict=False)
    except Exception as e:
        print(f"[ERROR] Red inválida para ICMP scan: {e}")
        return []

    dispositivos = []
    print(f"[INFO] ICMP scan en {red_cidr} (esto puede tardar)...")

    for ip in net.hosts():
        ip_str = str(ip)
        pkt = IP(dst=ip_str)/ICMP()
        try:
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if resp is not None:
                
                try:
                    host = socket.gethostbyaddr(ip_str)[0]
                except Exception:
                    host = "Desconocido"
                dispositivos.append({"ip": ip_str, "mac": None, "nombre": host})
        except Exception:
            pass
    return dispositivos

def escanear_red():

    red = obtener_red_local()
    if not red:
        print("[ERROR] No se pudo obtener la red local.")
        return []
    dispositivos = arp_scan(red_cidr=red, iface=None, timeout=3)
    if not dispositivos:
        print("[ADVERTENCIA] No se encontraron dispositivos. Verifica Npcap, AP isolation o firewall.")
        dispositivos = icmp_scan(red_cidr=red, timeout=2)
    return dispositivos

if __name__ == "__main__":
    
    red = obtener_red_local()
    print("[INFO] Red detectada:", red)
    dispositivos = escanear_red()
    if not dispositivos:
        print("[ADVERTENCIA] No se encontraron dispositivos con ARP/ICMP.")
    else:
        print("[RESULTADO] Dispositivos detectados:")
        for d in dispositivos:
            print(f" - {d['ip']} | MAC: {d['mac']} | Nombre: {d['nombre']}")
        
        

