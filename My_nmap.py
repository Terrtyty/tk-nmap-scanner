import tkinter as tk
from tkinter import ttk
from nmap import *


def scan_ports(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-p-')
    open_ports = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            lport = scanner[host][proto].keys()
            for port in lport:
                if scanner[host][proto][port]['state'] == 'open':
                    open_ports.append(port)
    return open_ports


def on_scan_clicked():
    target = entry_ip.get()
    open_ports = scan_ports(target)
    results = ', '.join(str(port) for port in open_ports)
    label_results.config(text=f"Відкриті порти: {results}")


root = tk.Tk()
root.title("Аналізатор вразливостей")

# Додати віджет для введення IP-адреси
label_ip = ttk.Label(root, text="IP:")
label_ip.grid(column=0, row=0, sticky="W", padx=5, pady=5)

entry_ip = ttk.Entry(root)
entry_ip.grid(column=1, row=0, padx=5, pady=5)

# Додати кнопку для запуску сканування
button_scan = ttk.Button(root, text="Сканувати", command=on_scan_clicked)
button_scan.grid(column=0, row=1, columnspan=2, padx=5, pady=5)

# Додати віджет для результатів сканування
label_results = ttk.Label(root, text="")
label_results.grid(column=0, row=2, columnspan=2, padx=5, pady=5)

root.mainloop()
