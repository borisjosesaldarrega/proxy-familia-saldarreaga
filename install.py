#!/usr/bin/env python3
import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd):
    """Ejecutar comando del sistema"""
    try:
        subprocess.run(cmd, shell=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error ejecutando comando: {cmd}")
        print(f"Error: {e}")
        return False

def main():
    print("Instalando Proxy Doméstico...")
    
    # Crear entorno virtual
    if not Path("venv").exists():
        print("Creando entorno virtual...")
        run_command("python3 -m venv venv")
    
    # Activar entorno virtual y instalar dependencias
    requirements = [
        "aiohttp>=3.8.0",
        "flask>=2.0.0", 
        "aiosqlite>=0.17.0",
        "asyncio",
        "pathlib"
    ]
    
    pip_cmd = "venv/bin/pip" if os.name != 'nt' else "venv\\Scripts\\pip"
    
    for package in requirements:
        print(f"Instalando {package}...")
        run_command(f"{pip_cmd} install {package}")
    
    # Crear estructura de directorios
    directories = [
        "config/certs",
        "data/block_lists", 
        "data/logs",
        "web/templates",
        "web/static"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"Directorio creado: {directory}")
    
    print("\n✅ Instalación completada!")
    print("\nPara iniciar el proxy:")
    print("  python main.py")
    print("\nEl panel web estará disponible en: http://localhost:8081")

if __name__ == "__main__":
    main()