import sys
import os
import time
import hashlib
import subprocess
import re
import psutil
import requests
import json
from datetime import datetime, timedelta, timezone
from plyer import notification
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, 
                             QPushButton, QTextBrowser, QProgressBar)
from PyQt5.QtCore import QTimer, QThread, pyqtSignal

# Função para calcular o hash SHA-256 de um arquivo
def calcular_sha256(arquivo):
    hasher = hashlib.sha256()
    with open(arquivo, 'rb') as f:
        while (chunk := f.read(8192)):
            hasher.update(chunk)
    return hasher.hexdigest()

# Função para atualizar os hashes de malware
def atualizar_hashes_malware():
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    url = "https://mb-api.abuse.ch/api/v1/"
    params = {
        'query': 'get_recent',
        'selector': 'time',
        'time': yesterday
    }

    response = requests.post(url, data=params)
    if response.status_code == 200:
        data = response.json()
        if data['query_status'] == 'ok':
            with open('malware_hashes.txt', 'w') as f:
                for sample in data['data']:
                    f.write(sample['sha256_hash'] + '\n')
        else:
            print("Nenhum dado encontrado.")
    else:
        print("Erro ao obter os hashes SHA-256.")

class RealtimeCheckThread(QThread):
    result_obtained = pyqtSignal(str)

    def __init__(self, virus_hashes, parent=None):
        super().__init__(parent)
        self.virus_hashes = virus_hashes

    def run(self):
        try:
            while True:
                self.realtime_check_logic()
                time.sleep(5)  # Exemplo: verificação a cada 5 segundos

        except Exception as e:
            self.result_obtained.emit(f"Erro durante a verificação em tempo real: {str(e)}")

    def realtime_check_logic(self):
        try:
            comando = r'wmic process get name,CommandLine /value'
            processo = subprocess.run(comando, shell=True, capture_output=True, text=True)
            if processo.returncode != 0:
                raise Exception(f"Erro ao executar o comando: {processo.stderr}")

            caminhos_arquivos = []
            for linha in processo.stdout.splitlines():
                if "CommandLine" in linha:
                    match = re.search(r'"([^"]*\\[^"]*\.(bat|vbs))"', linha)
                    if match:
                        caminho = match.group(1)
                        hash_arquivo = calcular_sha256(caminho)
                        if hash_arquivo in self.virus_hashes:
                            self.result_obtained.emit("Arquivo infectado encontrado, matando processo e deletando o arquivo.")
                            comando_final = f'wmic process where "commandline like \'%{caminho.replace("\\", "\\\\").replace("C:\\\\", "C:\\\\%")}%\'" call terminate'
                            subprocess.run(comando_final, shell=True, capture_output=True, text=True)
                            os.remove(caminho)
                            notification.notify(
                                title="Arquivo Infectado",
                                message="Arquivo infectado encontrado, matando processo e deletando o arquivo.",
                                app_name="AdrenalinAntivirus",
                            )
                        else:
                            print(f"Arquivo seguro: {caminho} {hash_arquivo}")

            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_info = proc.info
                    if proc_info['exe'] and proc_info['exe'].endswith('.exe') and os.path.exists(proc_info['exe']):
                        process_hash = calcular_sha256(proc_info['exe'])
                        if process_hash in self.virus_hashes:
                            self.result_obtained.emit("Arquivo infectado encontrado, matando processo e deletando o arquivo.")
                            p = psutil.Process(proc_info['pid'])
                            nome_processo = proc_info['name']
                            suspender_encerrar_processos(nome_processo)
                            try:
                                os.remove(proc_info['exe'])
                            except Exception as e:
                                print(f"Ocorreu um erro ao remover o arquivo: {e}")
                            notification.notify(
                                title="Arquivo Infectado",
                                message="Arquivo infectado encontrado, matando processo e deletando o arquivo.",
                                app_name="AdrenalinAntivirus",
                            )
                        else:
                            print(f"Arquivo seguro: {proc_info['exe']} {process_hash}")

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, psutil.TimeoutExpired):
                    print(f"Erro ao acessar informações do processo {proc_info['pid']} ({proc_info['name']}).")

        except Exception as e:
            print(f"Erro durante a execução do script: {str(e)}")

def listar_processos(nome_processo):
    processos_encontrados = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if nome_processo.lower() in proc.info['name'].lower():
                processos_encontrados.append(psutil.Process(proc.info['pid']))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processos_encontrados

def suspender_encerrar_processos(nome_processo):
    class ProcessoNaoEncontrado(Exception):
        pass

    class FalhaAoSuspender(Exception):
        pass

    class FalhaAoEncerrar(Exception):
        pass

    try:
        processos_encontrados = listar_processos(nome_processo)
        if not processos_encontrados:
            raise ProcessoNaoEncontrado(f"Nenhum processo com o nome '{nome_processo}' encontrado.")

        for processo_encontrado in processos_encontrados:
            try:
                processo_encontrado.suspend()
            except psutil.NoSuchProcess:
                pass
            except Exception as e:
                raise FalhaAoSuspender(f"Falha ao suspender o processo (PID {processo_encontrado.pid}): {e}")

        print("Processos suspensos:")
        for processo_encontrado in processos_encontrados:
            print(f"PID: {processo_encontrado.pid}, Nome: {processo_encontrado.name()}, Status: {processo_encontrado.status()}")

        time.sleep(3)

        for processo_encontrado in processos_encontrados:
            processos_filhos = processo_encontrado.children(recursive=True)
            for processo_filho in processos_filhos:
                try:
                    processo_filho.kill()
                except psutil.NoSuchProcess:
                    pass
                except Exception as e:
                    raise FalhaAoEncerrar(f"Falha ao encerrar o processo filho (PID {processo_filho.pid}): {e}")

        for processo_encontrado in processos_encontrados:
            try:
                processo_encontrado.kill()
            except psutil.NoSuchProcess:
                pass
            except Exception as e:
                raise FalhaAoEncerrar(f"Falha ao encerrar o processo principal (PID {processo_encontrado.pid}): {e}")

        print(f"Processos foram suspensos e encerrados com sucesso.")

    except ProcessoNaoEncontrado as e:
        print(f"Erro: {e}")

    except FalhaAoSuspender as e:
        print(f"Erro ao suspender processos: {e}")

    except FalhaAoEncerrar as e:
        print(f"Erro ao encerrar processos: {e}")

    except Exception as e:
        print(f"Ocorreu um erro inesperado: {e}")

class VirusScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AdrenalinAntivirus")
        self.setGeometry(100, 100, 600, 400)

        self.virus_hashes = set()
        self.init_ui()

        self.start_time = None
        self.system_info_timer = QTimer(self)
        self.system_info_timer.timeout.connect(self.show_system_info)

        self.carregar_hashes_malware()

        self.realtime_thread = RealtimeCheckThread(self.virus_hashes)
        self.realtime_thread.result_obtained.connect(self.handle_realtime_result)
        self.realtime_thread.start()

    def init_ui(self):
        layout = QVBoxLayout()

        self.drive_path_label = QLabel("Caminho do Disco a Verificar:")
        self.drive_path_edit = QLineEdit()
        self.scan_button = QPushButton("Varrer Disco")
        self.system_info_button = QPushButton("Mostrar Informações do Sistema")
        self.result_output = QTextBrowser()
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)

        layout.addWidget(self.drive_path_label)
        layout.addWidget(self.drive_path_edit)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.system_info_button)
        layout.addWidget(self.result_output)
        layout.addWidget(self.progress_bar)

        self.setLayout(layout)

        self.scan_button.clicked.connect(self.scan_drive)
        self.system_info_button.clicked.connect(self.toggle_system_info)

    def carregar_hashes_malware(self):
        try:
            with open('malware_hashes.txt', 'r') as f:
                self.virus_hashes = {line.strip() for line in f}
        except FileNotFoundError:
                       self.result_output.append("Arquivo de hashes de malware não encontrado.")

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def scan_drive(self):
        try:
            drive_path = self.drive_path_edit.text()
            if not os.path.exists(drive_path):
                self.result_output.setText("Caminho de disco inválido.")
                return
            self.result_output.clear()
            self.result_output.append(f"Verificando arquivos no disco {drive_path}...")
            arquivos_infectados = []

            num_files = sum([len(files) for _, _, files in os.walk(drive_path)])
            self.progress_bar.setMaximum(num_files)
            self.progress_bar.setValue(0)
            self.progress_bar.setVisible(True)

            self.start_time = time.time()

            self.scan_thread = ScanThread(drive_path, self.virus_hashes)
            self.scan_thread.progress_updated.connect(self.update_progress)
            self.scan_thread.file_infected.connect(self.handle_infected_file)
            self.scan_thread.finished.connect(self.handle_scan_finished)

            self.scan_thread.start()
        except Exception as e:
            print(f"Erro durante a verificação em segundo plano: {e}")

    def handle_infected_file(self, file_path):
        self.result_output.append(f"Arquivo infectado removido: {file_path}")
        notification.notify(
            title="Arquivo Infectado",
            message=f"Arquivo infectado removido: {file_path}",
            app_name="AdrenalinAntivirus",
        )

    def handle_scan_finished(self, arquivos_infectados):
        self.progress_bar.setVisible(False)
        if len(arquivos_infectados) > 0:
            self.result_output.append(f"\nForam encontrados {len(arquivos_infectados)} arquivo(s) infectado(s)!")
        else:
            self.result_output.append("\nNenhuma ameaça foi encontrada.")
        elapsed_time = time.time() - self.start_time
        self.result_output.append(f"\nTempo total de verificação: {elapsed_time:.2f} segundos")

    def toggle_system_info(self):
        if self.system_info_timer.isActive():
            self.system_info_timer.stop()
            self.system_info_button.setText("Mostrar Informações do Sistema")
        else:
            self.system_info_timer.start(1000)
            self.system_info_button.setText("Parar de Exibir Informações")

    def show_system_info(self):
        cpu_percent = psutil.cpu_percent()
        ram_usage = psutil.virtual_memory().percent
        disk_usage = psutil.disk_usage('C:\\').percent

        system_info = f"CPU Usage: {cpu_percent:.1f}%\nRAM Usage: {ram_usage:.1f}%\nDisk Usage: {disk_usage:.1f}%"
        self.result_output.setPlainText(system_info)

    def handle_realtime_result(self, result):
        self.result_output.append(result)

class ScanThread(QThread):
    progress_updated = pyqtSignal(int)
    file_infected = pyqtSignal(str)
    finished = pyqtSignal(list)

    def __init__(self, drive_path, virus_hashes):
        super().__init__()
        self.drive_path = drive_path
        self.virus_hashes = virus_hashes

    def run(self):
        arquivos_infectados = []
        num_files_scanned = 0
        for root, _, files in os.walk(self.drive_path):
            for file in files:
                file_path = os.path.join(root, file)
                if self.check_for_virus(file_path):
                    arquivos_infectados.append(file_path)
                    try:
                        os.remove(file_path)
                        self.file_infected.emit(file_path)
                    except OSError as e:
                        print(f"Erro ao remover o arquivo {file_path}: {e}")
                num_files_scanned += 1
                self.progress_updated.emit(num_files_scanned)

        self.finished.emit(arquivos_infectados)

    def check_for_virus(self, file_path):
        try:
            if file_path.lower().endswith((
                ".exe", ".bat", ".com", ".pps", ".dbx", ".ddl", ".inbox", ".eml",
                ".vbs", ".jse", ".ws", ".wsc", ".ps1", ".ps1xml", ".ps2", ".psc1",
                ".psc2", ".msh", ".msh1", ".msh2", ".mshxml", ".msh1xml", ".msh2xml",
                ".scf", ".lnk", ".inf", ".reg")):
                arquivo_sha256 = hashlib.sha256()
                with open(file_path, "rb") as f:
                    for pedaco in iter(lambda: f.read(4096), b""):
                        arquivo_sha256.update(pedaco)
                return arquivo_sha256.hexdigest() in self.virus_hashes
        except OSError as e:
            print(f"Erro ao verificar o arquivo {file_path}: {e}")

        return False

if __name__ == "__main__":
    # Atualiza os hashes de malware antes de iniciar a aplicação
    atualizar_hashes_malware()

    app = QApplication(sys.argv)
    scanner_app = VirusScannerApp()
    scanner_app.show()
    sys.exit(app.exec_())

