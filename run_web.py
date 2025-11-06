# run_web.py
from web.app import create_web_app

if __name__ == "__main__":
    # Simulación mínima para pruebas
    app = create_web_app(proxy_server=None, config={})
    app.run(host="localhost", port=8081, debug=True)
