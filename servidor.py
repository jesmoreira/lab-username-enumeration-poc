from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

# "base de dados" de usuários válidos.
# só temos os nomes, não as senhas.
USUARIOS_VALIDOS = ["admin", "suporte", "gato_ninja"]

class ServidorVulneravel(BaseHTTPRequestHandler):

    def do_GET(self):
        # Se alguém simplesmente acessar o site, entregamos a página de login.
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            with open('index.html', 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Pagina nao encontrada")

    def do_POST(self):
        # Se alguém enviar dados para /login...
        if self.path == '/login':
            # 1. Ler os dados enviados no formulário
            content_length = int(self.headers['Content-Length'])
            post_data_bytes = self.rfile.read(content_length)
            post_data_str = post_data_bytes.decode('utf-8')
            post_data = urllib.parse.parse_qs(post_data_str)

            username_submetido = post_data.get('username', [''])[0]

            # 2. <<< AQUI ESTÁ A VULNERABILIDADE >>>
            # Verificamos se o nome de usuário existe na nossa lista.
            if username_submetido in USUARIOS_VALIDOS:
                # Se EXISTE, retornamos uma mensagem específica.
                resposta_html = b"<h1>Senha incorreta!</h1>"
            else:
                # Se NAO EXISTE, retornamos uma mensagem genérica.
                resposta_html = b"<h1>Usuario ou senha invalidos.</h1>"

            # 3. Enviamos a resposta para o navegador
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(resposta_html)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Endpoint nao encontrado")


# Inicia o servidor na porta 8000
print("Servidor iniciado em http://localhost:8000")
print("Pressione Ctrl+C para parar o servidor.")
httpd = HTTPServer(('localhost', 8000), ServidorVulneravel)
httpd.serve_forever()
