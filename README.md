🛡️ Trinity Pentest Framework
O Trinity Pentest Framework é um conjunto de ferramentas para testes de penetração, focado em reconhecimento, varredura de diretórios, análise de arquivos sensíveis e envio de emails de phishing.

🚀 Funcionalidades:
✔ Phishing – Envio de emails maliciosos para simulação de ataques.
✔ Reconhecimento – Coleta de informações do alvo usando Nmap.
✔ Escaneamento de Arquivos Sensíveis – Busca por arquivos críticos no sistema.
✔ Varredura de Diretórios – Identifica diretórios e caminhos comuns em sistemas.
✔ Geração de Relatórios PDF – Registra todos os dados coletados em um relatório estruturado.
✔ Interface CLI – Uso simplificado por linha de comando.

📌 Requisitos:
🔹 Python 3.x
🔹 Bibliotecas necessárias: scapy, socket, smtplib, ssl, fpdf, nmap, psutil, sqlite3

Instale as dependências com:
pip install scapy fpdf nmap psutil

🔧 Como Usar:
📍 Exibir a Logo:
python trinity.py

📍 Enviar Email de Phishing:
python trinity.py -p

📍 Realizar Reconhecimento do Alvo:
python trinity.py -r -i <IP_ALVO>

📍 Escanear Arquivos Sensíveis:
python trinity.py -f -i <IP_ALVO>

📍 Buscar Diretórios no Alvo:
python trinity.py -d -i <IP_ALVO>

⚠ Aviso Legal:
O uso deste script para fins não autorizados é ilegal e pode resultar em consequências severas. Utilize apenas para testes de segurança legítimos e ambientes autorizados.

