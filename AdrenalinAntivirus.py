import sys
import os
import pymongo
import psutil
from plyer import notification 
import time
import hashlib
import subprocess
import re
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextBrowser, QProgressBar
from PyQt5.QtCore import QTimer, QThread, pyqtSignal

# Função para calcular o hash SHA-256 de um arquivo
def calcular_sha256(arquivo):
    hasher = hashlib.sha256()
    with open(arquivo, 'rb') as f:
        while (chunk := f.read(8192)):
            hasher.update(chunk)
    return hasher.hexdigest()

class RealtimeCheckThread(QThread):
    result_obtained = pyqtSignal(str)

    def __init__(self, all_documents, parent=None):
        super().__init__(parent)
        self.all_documents = all_documents

    def run(self):
        try:
            while True:
                # Sua lógica de verificação em tempo real aqui
                self.realtime_check_logic()
                time.sleep(5)  # Exemplo: verificação a cada 5 segundos

        except Exception as e:
            self.result_obtained.emit(f"Erro durante a verificação em tempo real: {str(e)}")

    def realtime_check_logic(self):
        try:
            # Comando a ser executado
            comando = r'wmic process get name,CommandLine /value'

            # Executar o comando e capturar a saída
            processo = subprocess.run(comando, shell=True, capture_output=True, text=True)

            # Verificar se ocorreu algum erro
            if processo.returncode != 0:
                raise Exception(f"Erro ao executar o comando: {processo.stderr}")

            # Filtrar o resultado para obter apenas os diretórios de arquivos .bat e .vbs
            caminhos_arquivos = []
            for linha in processo.stdout.splitlines():
                if "CommandLine" in linha:
                    match = re.search(r'"([^"]*\\[^"]*\.(bat|vbs))"', linha)
                    if match:
                        caminho = match.group(1)
                        # Calcular o hash do arquivo
                        hash_arquivo = calcular_sha256(caminho)

                        # Verificar se o hash está na lista de hashes do MongoDB
                        hash_encontrado = any(hash_arquivo in doc.get("hashes", []) for doc in self.all_documents)

                        if hash_encontrado:
                            self.result_obtained.emit(f"Arquivo infectado encontrado, matando processo e deletando o arquivo.")

                            # Criar a variável do comando final para cada caminho individualmente
                            comando_final = f'wmic process where "commandline like \'%{caminho.replace("\\", "\\\\").replace("C:\\\\", "C:\\\\%")}%\'" call terminate'

                            # Imprimir os comandos finais para verificar se estão corretos
                            print("Comando final:")
                            print(comando_final.replace("'%\" call terminate", "\"\""))

                            # Enviar para o CMD usando subprocess
                            subprocess.run(comando_final, shell=True, capture_output=True, text=True)
                            os.remove(caminho)
                            notification.notify(
                                title="Arquivo Infectado",
                                message="Arquivo infectado encontrado, matando processo e deletando o arquivo.",
                                app_name="AdrenalinAntivirus",
                            )
                        else:
                            self.result_obtained.emit(f"Arquivo seguro: {caminho} {hash_arquivo}")

            # Obtenha a lista de processos
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_info = proc.info

                    # Verifica se o processo é um executável .exe
                    if proc_info['exe'] and proc_info['exe'].endswith('.exe') and os.path.exists(proc_info['exe']):
                        # Calcule o hash sha-256 do executável do processo
                        process_hash = calcular_sha256(proc_info['exe'])

                        # Calcular os hashes dos documentos no MongoDB
                        mongo_hashes = [hash for doc in self.all_documents for hash in doc.get("hashes", [])]

                        # Compare o hash com os hashes carregados do MongoDB
                        if process_hash and process_hash not in mongo_hashes:
                            # Nenhum hash correspondente encontrado, imprimir informações e decidir a ação adequada
                            print(f"Processo {proc_info['pid']} ({proc_info['name']}) com hash não correspondente: {process_hash}")
                        else:
                            # Aqui, você pode decidir se deseja terminar o processo ou tomar outra ação
                            self.result_obtained.emit(f"Arquivo infectado encontrado, matando processo e deletando o arquivo.")
                            p = psutil.Process(proc_info['pid'])
                            p.kill()  # Matar o processo principal e todos os seus processos filhos
                            os.remove(proc_info['exe'])
                            notification.notify(
                                title="Arquivo Infectado",
                                message="Arquivo infectado encontrado, matando processo e deletando o arquivo.",
                                app_name="AdrenalinAntivirus",
                            )
                            

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, psutil.TimeoutExpired):
                    # Lidar com exceções específicas do psutil que podem ocorrer ao acessar informações do processo
                    print(f"Erro ao acessar informações do processo {proc_info['pid']} ({proc_info['name']}).")

        except Exception as e:
            print(f"Erro durante a execução do script: {str(e)}")

class VirusScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AdrenalinAntivirus")
        self.setGeometry(100, 100, 600, 400)

        uri = "mongodb+srv://rieidigamer:rieidi@cluster0.zhgdqi8.mongodb.net/?retryWrites=true&w=majority"
        client = pymongo.MongoClient(uri)
        database = client["AdrenalinATV"]
        collection = database["Antivirus"]

        # Carregar e armazenar os hashes dos vírus
        self.virus_hashes = set()
        virus_data = list(collection.find({}, {"_id": 0, "hashes": 1}))
        for virus in virus_data:
            self.virus_hashes.update(virus.get("hashes", []))

        # Armazenar os documentos como um atributo da instância
        self.all_documents = list(collection.find({}, {"_id": 0, "hashes": 1}))

        client.close()

        self.progress_bar = None

        self.init_ui()

        self.start_time = None
        self.system_info_timer = QTimer(self)
        self.system_info_timer.timeout.connect(self.show_system_info)

        # Configurar o timer para executar a função de verificação em tempo real a cada 5 segundos
        self.realtime_thread = RealtimeCheckThread(self.all_documents)
        self.realtime_thread.result_obtained.connect(self.handle_realtime_result)
        self.realtime_thread.start()

    def init_ui(self):
        layout = QVBoxLayout()

        # Widgets para entrada do caminho do disco a ser verificado
        self.drive_path_label = QLabel("Caminho do Disco a Verificar:")
        self.drive_path_edit = QLineEdit()

        # Botão de varredura
        self.scan_button = QPushButton("Varrer Disco")

        # Botão para mostrar informações do sistema
        self.system_info_button = QPushButton("Mostrar Informações do Sistema")

        # Saída de resultados
        self.result_output = QTextBrowser()

        self.progress_bar = QProgressBar()  # Criação da barra de progresso
        self.progress_bar.setVisible(False)

        # Adicionar widgets ao layout
        layout.addWidget(self.drive_path_label)
        layout.addWidget(self.drive_path_edit)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.system_info_button)
        layout.addWidget(self.result_output)

        # Conectar sinais aos slots
        self.scan_button.clicked.connect(self.scan_drive)
        self.system_info_button.clicked.connect(self.toggle_system_info)

        self.setLayout(layout)

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
            self.progress_bar.setValue(False)
            self.progress_bar.setVisible(True)

            self.start_time = time.time()

            # Criar uma instância da classe de verificação em segundo plano
            self.scan_thread = ScanThread(drive_path, self.virus_hashes, self.all_documents)
            self.scan_thread.progress_updated.connect(self.update_progress)
            self.scan_thread.file_infected.connect(self.handle_infected_file)
            self.scan_thread.finished.connect(self.handle_scan_finished)

            # Iniciar a verificação em segundo plano
            self.scan_thread.start()
            self.progress_bar.setVisible(False)
        except Exception as e:
            print(f"Erro durante a verificação em segundo plano: {e}")


    def handle_infected_file(self, file_path):
        self.result_output.append(f"Arquivo infectado removido: {file_path}")

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
        disk_usage = psutil.disk_usage(os.path.abspath(".")).percent

        system_info = f"CPU Usage: {cpu_percent:.1f}%\nRAM Usage: {ram_usage:.1f}%\nDisk Usage: {disk_usage:.1f}%"
        self.result_output.setPlainText(system_info)

    def handle_realtime_result(self, result):
        self.result_output.append(result)

class ScanThread(QThread):
    progress_updated = pyqtSignal(int)
    file_infected = pyqtSignal(str)
    finished = pyqtSignal(list)


    def __init__(self, drive_path, virus_hashes, all_documents):
        super().__init__()
        self.drive_path = drive_path
        self.virus_hashes = virus_hashes
        self.all_documents = all_documents

    def run(self):
        
        arquivos_infectados = []

        for root, _, files in os.walk(self.drive_path):
            for file in files:
                file_path = os.path.join(root, file)
                if self.check_for_virus(file_path):
                    arquivos_infectados.append(file_path)
                    try:
                        os.remove(file_path)
                        self.file_infected.emit(file_path)
                        notification.notify(
                            title="Arquivo Infectado",
                            message="Arquivo infectado encontrado, deletando o arquivo.",
                            app_name="AdrenalinAntivirus",
                        )
                        
                    except OSError as e:
                        print(f"Erro ao remover o arquivo {file_path}: {e}")


        self.finished.emit(arquivos_infectados)

    def check_for_virus(self, file_path):
        try:
            if file_path.lower().endswith((".exe", ".bat", ".com", ".pps", ".dbx", ".ddl", ".inbox", ".eml",
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
    app = QApplication(sys.argv)
    scanner_app = VirusScannerApp()
    scanner_app.show()
    sys.exit(app.exec_())

