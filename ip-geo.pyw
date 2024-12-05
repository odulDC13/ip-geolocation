import requests
import ipaddress
import tkinter as tk
from tkinter import messagebox, ttk
from PIL import Image, ImageTk

# Función para validar si una IP es pública
def es_ip_publica(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not ip_obj.is_private
    except ValueError:
        return False

# Función para obtener información de IP
def obtener_info_ip(ip):
    if not es_ip_publica(ip):
        # Información simulada para IP privadas
        return {
            'ip': ip,
            'city': 'Red Local',
            'region': 'Red Interna',
            'country': 'Sin Información',
            'org': 'Sin Información',
            'timezone': 'Sin Información',
            'lat': '0',
            'lon': '0',
            'asn': 'Sin Información',
            'isp': 'Sin Información',
            'postal': 'Sin Información',
            'proxy': 'No',
            'vpn': 'No',
        }
    
    try:
        info_ipinfo = requests.get(
            f'https://ipinfo.io/{ip}/json',
            headers={'User-Agent': 'Mozilla/5.0'}
        ).json()

        info_ip_api = requests.get(
            f'http://ip-api.com/json/{ip}',
            headers={'User-Agent': 'Mozilla/5.0'}
        ).json()

        info_ipapi = requests.get(
            f'https://ipapi.co/{ip}/json/',
            headers={'User-Agent': 'Mozilla/5.0'}
        ).json()

        info = {
            'ip': ip,
            'city': info_ipinfo.get('city', info_ip_api.get('city', info_ipapi.get('city'))),
            'region': info_ipinfo.get('region', info_ip_api.get('region', info_ipapi.get('region'))),
            'country': info_ipinfo.get('country', info_ip_api.get('country', info_ipapi.get('country'))),
            'org': info_ipinfo.get('org', info_ip_api.get('org', info_ipapi.get('org'))),
            'timezone': info_ipinfo.get('timezone', info_ip_api.get('timezone', info_ipapi.get('timezone'))),
            'lat': info_ipinfo.get('loc', info_ip_api.get('lat', info_ipapi.get('latitude'))),
            'lon': info_ipinfo.get('loc', info_ip_api.get('lon', info_ipapi.get('longitude'))),
            'asn': info_ipinfo.get('org', info_ip_api.get('as', info_ipapi.get('asn'))),
            'isp': info_ipinfo.get('org', info_ip_api.get('isp', info_ipapi.get('isp'))),
            'postal': info_ipinfo.get('postal', info_ip_api.get('zip', info_ipapi.get('postal'))),
            'proxy': info_ip_api.get('proxy'),
            'vpn': info_ip_api.get('vpn'),
        }
        return info
    except Exception as e:
        return f"Error al obtener la información: {e}"

# Función para manejar la búsqueda y mostrar resultados
def buscar_ip():
    ip = entry_ip.get().strip()
    if not ip:
        messagebox.showerror("Error", "Por favor, introduce una dirección IP.")
        return

    info = obtener_info_ip(ip)
    if isinstance(info, dict):
        result_text = f"""
        ‣ IP: {info['ip']}
        ‣ Ciudad: {info['city']}
        ‣ Región: {info['region']}
        ‣ País: {info['country']}
        ‣ Organización: {info['org']}
        ‣ Zona Horaria: {info['timezone']}
        ‣ Latitud: {info['lat']}
        ‣ Longitud: {info['lon']}
        ‣ ASN: {info['asn']}
        ‣ Proveedor de Internet: {info['isp']}
        ‣ Código Postal: {info['postal']}
        ‣ Proxy: {info['proxy']}
        ‣ VPN: {info['vpn']}
        """
        text_output.delete(1.0, tk.END)
        text_output.insert(tk.END, result_text)
    else:
        messagebox.showerror("Error", info)

# Interfaz gráfica con Tkinter
root = tk.Tk()
root.title("AKIRA")
root.geometry("600x500")
root.configure(bg="#2c2c2c")

# Título
titulo = tk.Label(root, text="Consulta de Información de IP", bg="#2c2c2c", fg="white", font=("Arial", 14, "bold"))
titulo.pack(pady=10)

# Imagen central
imagen_original = Image.open("picture.png")  # Cambiar a la ruta correcta
imagen_redimensionada = imagen_original.resize((150, 150), Image.LANCZOS)
icono = ImageTk.PhotoImage(imagen_redimensionada)


label_imagen = tk.Label(root, image=icono, bg="#2c2c2c")
label_imagen.pack(pady=10)

# Entrada para IP
label_ip = tk.Label(root, text="Introduce una dirección IP:", bg="#2c2c2c", fg="white", font=("Arial", 12))
label_ip.pack(pady=5)

entry_ip = tk.Entry(root, width=40, font=("Arial", 12))
entry_ip.pack(pady=5)

# Botón para buscar
style = ttk.Style()
style.theme_use("clam")
style.configure("TButton", font=("Arial", 10, "bold"), foreground="white", background="#4CAF50")
style.map("TButton", background=[("active", "#45a049")])

button_buscar = ttk.Button(root, text="Buscar Información", command=buscar_ip)
button_buscar.pack(pady=10)

# Área de texto para resultados
text_output = tk.Text(root, height=12, width=70, font=("Arial", 10), bg="#1e1e1e", fg="white")
text_output.pack(pady=10)

# Ejecutar aplicación
root.mainloop()
