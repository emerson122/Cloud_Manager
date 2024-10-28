import os
import re
import time
import subprocess
import psutil
import datetime
from collections import defaultdict
from pathlib import Path

class WebServerMonitor:
    def __init__(self, server_type="apache"):
        """
        Inicializa el monitor del servidor web
        server_type: "apache" o "nginx"
        """
        self.server_type = server_type.lower()
        
        # Configuración según el tipo de servidor
        if self.server_type == "apache":
            self.service_name = "apache2" if os.path.exists("/etc/apache2") else "httpd"
            self.log_path = "/var/log/apache2/access.log" if os.path.exists("/var/log/apache2") else "/var/log/httpd/access_log"
            self.error_log = "/var/log/apache2/error.log" if os.path.exists("/var/log/apache2") else "/var/log/httpd/error_log"
        else:  # nginx
            self.service_name = "nginx"
            self.log_path = "/var/log/nginx/access.log"
            self.error_log = "/var/log/nginx/error.log"
    
    def check_server_status(self):
        """Verifica el estado del servidor web"""
        try:
            service = psutil.Process(self._get_pid())
            memory_usage = service.memory_percent()
            cpu_usage = service.cpu_percent(interval=1)
            connections = len(service.connections())
            
            return {
                "status": "running",
                "memory_usage": f"{memory_usage:.1f}%",
                "cpu_usage": f"{cpu_usage:.1f}%",
                "connections": connections,
                "uptime": self._get_uptime(service)
            }
        except:
            return {"status": "stopped"}

    def _get_pid(self):
        """Obtiene el PID del servidor web"""
        try:
            if os.path.exists("/var/run"):
                pid_file = f"/var/run/{self.service_name}/{self.service_name}.pid"
                with open(pid_file, 'r') as f:
                    return int(f.read().strip())
        except:
            # Buscar el proceso por nombre si no se encuentra el archivo PID
            for proc in psutil.process_iter(['pid', 'name']):
                if self.service_name in proc.info['name'].lower():
                    return proc.info['pid']
        return None

    def _get_uptime(self, process):
        """Calcula el tiempo de actividad del servidor"""
        create_time = datetime.datetime.fromtimestamp(process.create_time())
        uptime = datetime.datetime.now() - create_time
        days = uptime.days
        hours, remainder = divmod(uptime.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{days}d {hours}h {minutes}m {seconds}s"

    def analyze_recent_logs(self, num_lines=1000):
        """Analiza las últimas líneas del log de acceso"""
        if not os.path.exists(self.log_path):
            return {"error": "Archivo de log no encontrado"}

        ip_counts = defaultdict(int)
        status_counts = defaultdict(int)
        path_counts = defaultdict(int)
        
        # Patrón para logs de Apache/Nginx
        pattern = r'(\d+\.\d+\.\d+\.\d+).*?"([A-Z]+) ([^"]+).*?" (\d{3})'
        
        try:
            # Leer las últimas líneas del log
            with open(self.log_path, 'r') as f:
                # Usar tail si está disponible para mejor rendimiento
                if os.path.exists("/usr/bin/tail"):
                    log_lines = subprocess.check_output(
                        ["tail", "-n", str(num_lines), self.log_path]
                    ).decode().split("\n")
                else:
                    log_lines = f.readlines()[-num_lines:]

            for line in log_lines:
                match = re.search(pattern, line)
                if match:
                    ip, method, path, status = match.groups()
                    ip_counts[ip] += 1
                    status_counts[status] += 1
                    path_counts[path] += 1

            # Obtener las IPs más frecuentes
            top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # Obtener las rutas más solicitadas
            top_paths = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:10]

            return {
                "top_ips": dict(top_ips),
                "status_codes": dict(status_counts),
                "top_paths": dict(top_paths)
            }
        except Exception as e:
            return {"error": f"Error al analizar logs: {str(e)}"}

    def check_security(self):
        """Realiza verificaciones básicas de seguridad"""
        security_issues = []
        
        # Verificar permisos de archivos de configuración
        config_paths = {
            "apache": ["/etc/apache2", "/etc/httpd"],
            "nginx": ["/etc/nginx"]
        }
        
        for path in config_paths[self.server_type]:
            if os.path.exists(path):
                # Verificar permisos
                stat = os.stat(path)
                if stat.st_mode & 0o777 != 0o755:
                    security_issues.append(f"Permisos incorrectos en {path}")
        
        # Verificar errores comunes en los logs
        try:
            with open(self.error_log, 'r') as f:
                error_lines = f.readlines()[-100:]  # últimas 100 líneas
                for line in error_lines:
                    if "permission denied" in line.lower():
                        security_issues.append("Errores de permisos detectados")
                        break
                    if "directory index forbidden" in line.lower():
                        security_issues.append("Listado de directorios puede estar habilitado")
                        break
        except:
            security_issues.append("No se puede acceder al log de errores")

        return security_issues if security_issues else "No se encontraron problemas de seguridad evidentes"

    def restart_server(self):
        """Reinicia el servidor web"""
        try:
            subprocess.run(["systemctl", "restart", self.service_name], check=True)
            return "Servidor reiniciado correctamente"
        except subprocess.CalledProcessError as e:
            return f"Error al reiniciar el servidor: {str(e)}"

def main():
    # Detectar el tipo de servidor instalado
    server_type = "apache" if os.path.exists("/etc/apache2") or os.path.exists("/etc/httpd") else "nginx"
    monitor = WebServerMonitor(server_type)
    
    while True:
        print("\n=== Monitor de Servidor Web ===")
        print(f"Tipo de servidor: {server_type.upper()}")
        print("\n1. Ver estado del servidor")
        print("2. Analizar logs recientes")
        print("3. Verificar seguridad")
        print("4. Reiniciar servidor")
        print("5. Salir")
        
        option = input("\nSeleccione una opción: ")
        
        if option == "1":
            status = monitor.check_server_status()
            print("\nEstado del servidor:")
            for key, value in status.items():
                print(f"{key}: {value}")
                
        elif option == "2":
            print("\nAnalizando logs...")
            analysis = monitor.analyze_recent_logs()
            
            if "error" in analysis:
                print(f"Error: {analysis['error']}")
            else:
                print("\nTop 10 IPs:")
                for ip, count in analysis["top_ips"].items():
                    print(f"{ip}: {count} requests")
                
                print("\nCódigos de estado:")
                for status, count in analysis["status_codes"].items():
                    print(f"{status}: {count}")
                
                print("\nRutas más solicitadas:")
                for path, count in analysis["top_paths"].items():
                    print(f"{path}: {count}")
                
        elif option == "3":
            print("\nVerificando seguridad...")
            security_check = monitor.check_security()
            print(security_check)
            
        elif option == "4":
            confirm = input("\n¿Está seguro de que desea reiniciar el servidor? (s/n): ")
            if confirm.lower() == 's':
                result = monitor.restart_server()
                print(result)
            
        elif option == "5":
            print("\n¡Hasta luego!")
            break
            
        else:
            print("\nOpción no válida")

if __name__ == "__main__":
    main()