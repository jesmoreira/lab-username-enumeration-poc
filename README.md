# [PoC] Enumeração de Usuário via Resposta Diferencial
=============================================================================
Author: [Jéssica Moreira]
Date: 13/08/2025
Target: Ambiente Local (localhost:8000)
Description: Análise e exploração de uma falha de enumeração de usuário em um endpoint de autenticação. 
A vulnerabilidade é explorada via análise diferencial da resposta HTTP utilizando a ferramenta ffuf.

![Linguagem](https://img.shields.io/badge/Python-3.8%2B-blue)
![Licença](https://img.shields.io/badge/License-MIT-green)
=============================================================================


## [CVE-2025-XXXX] Análise da Vulnerabilidade

- **Vetor de Ataque:** Enumeração de Identidade
- **Endpoint Afetado:** `/login` (método `POST`)
- **Resumo Técnico:** O endpoint de autenticação exibe um comportamento de resposta não-uniforme. Ao receber um `payload` com um `username` válido, a API retorna a string *"Senha incorreta!"*. Para um `username` inválido, a resposta contém a string *"Usuario ou senha invalidos."*. Essa discrepância permite a um ator malicioso diferenciar entre contas existentes e não existentes.

## Ambiente de Testes (Lab Setup)

Para replicar a vulnerabilidade, o seguinte ambiente foi configurado.

<details>
<summary><code>./frontend/index.html</code></summary>

```html
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <title>Login Secreto</title>
</head>
<body>
    <h2>Área Restrita</h2>
    <form action="/login" method="post">
        <input type="text" name="username" placeholder="Nome de Usuário" required>
        <input type="password" name="password" placeholder="Senha" required>
        <button type="submit">Entrar</button>
    </form>
</body>
</html>
</details>



<details>
<summary><code>./backend/servidor.py</code></summary>

Python

from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

USUARIOS_VALIDOS = ["admin", "suporte", "gato_ninja"]

class ServidorVulneravel(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/login':
            content_length = int(self.headers['Content-Length'])
            post_data_bytes = self.rfile.read(content_length)
            post_data_str = post_data_bytes.decode('utf-8')
            post_data = urllib.parse.parse_qs(post_data_str)
            username_submetido = post_data.get('username', [''])[0]

            # VULNERABILITY: Response bifurcation based on user existence
            if username_submetido in USUARIOS_VALIDOS:
                resposta_html = b"<h1>Senha incorreta!</h1>"
            else:
                resposta_html = b"<h1>Usuario ou senha invalidos.</h1>"

            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(resposta_html)

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            with open('index.html', 'rb') as f:
                self.wfile.write(f.read())

print("Servidor iniciado em http://localhost:8000")
httpd = HTTPServer(('localhost', 8000), ServidorVulneravel)
httpd.serve_forever()
</details>


Prova de Conceito (PoC): Executando o Exploit
Payload (./usuarios.txt)
admin
root
teste
suporte
user
gato_ninja



# Script para executar a enumeração de usuários
ffuf \
  -w "usuarios.txt" \
  -u "http://localhost:8000/login" \
  -X POST \
  -d "username=FUZZ&password=123" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -mr "Senha incorreta"


Remediation: Aplicando o Patch
A correção envolve a normalização da resposta do endpoint. A mudança é apresentada abaixo no formato diff.

Diff

--- a/backend/servidor.py
+++ b/backend/servidor.py
@@ -14,12 +14,8 @@
             post_data = urllib.parse.parse_qs(post_data_str)
             username_submetido = post_data.get('username', [''])[0]
 
-            # VULNERABILITY: Response bifurcation based on user existence
-            if username_submetido in USUARIOS_VALIDOS:
-                resposta_html = b"<h1>Senha incorreta!</h1>"
-            else:
-                resposta_html = b"<h1>Usuario ou senha invalidos.</h1>"
-
+            # PATCH: Response is now generic, preventing enumeration.
+            resposta_html = b"<h1>Nome de usuario ou senha invalidos.</h1>"
+            
             self.send_response(200)
             self.send_header('Content-type', 'text/html; charset=utf-8')
             self.end_headers()
