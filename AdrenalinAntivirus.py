import sys
import os
import psutil
import time
import hashlib
import subprocess
import win32com.shell.shell as shell
from win32com.shell import shellcon

from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextBrowser, QProgressBar
from PyQt5.QtCore import QTimer
from PyQt5.QtGui import QIntValidator
import pymongo

class VirusScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AdrenalinAntivirus")
        self.setGeometry(100, 100, 600, 400)

        # Conectar ao banco de dados MongoDB
        uri = "mongodb+srv://rieidigamer:rieidi@cluster0.zhgdqi8.mongodb.net/?retryWrites=true&w=majority"
        client = pymongo.MongoClient(uri)
        database = client["antivirus"]
        collection = database["antivirus1"]

        # Carregar e armazenar os hashes dos vírus
        self.virus_hashes = set()
        virus_data = list(collection.find({}, {"_id": 0, "hashes": 1}))
        for virus in virus_data:
            self.virus_hashes.update(virus.get("hashes", []))

        client.close()

        self.init_ui()

        self.start_time = None
        self.system_info_timer = QTimer(self)
        self.system_info_timer.timeout.connect(self.show_system_info)

    def init_ui(self):
        layout = QVBoxLayout()

        # Widgets para entrada do caminho do disco a ser verificado
        self.drive_path_label = QLabel("Caminho do Disco a Verificar:")
        self.drive_path_edit = QLineEdit()
        self.drive_path_edit.setValidator(QIntValidator())

        # Botão de varredura
        self.scan_button = QPushButton("Varrer Disco")

        # Botão para executar sfc /scannow
        self.sfc_button = QPushButton("Executar sfc /scannow")

        # Barra de progresso
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)

        # Botão para mostrar informações do sistema
        self.system_info_button = QPushButton("Mostrar Informações do Sistema")

        # Saída de resultados
        self.result_output = QTextBrowser()

        # Adicionar widgets ao layout
        layout.addWidget(self.drive_path_label)
        layout.addWidget(self.drive_path_edit)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.sfc_button)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.system_info_button)
        layout.addWidget(self.result_output)

        # Conectar sinais aos slots
        self.scan_button.clicked.connect(self.scan_drive)
        self.sfc_button.clicked.connect(self.run_sfc)
        self.system_info_button.clicked.connect(self.toggle_system_info)  # Corrigido aqui

        self.setLayout(layout)

    def check_for_virus(self, file_path):
        try:
            if file_path.lower().endswith((".exe", ".bat", ".com", ".pps", ".dbx", ".ddl", ".inbox", ".eml",
                ".mbx", ".mms", ".nch", ".ods", ".sys", ".bin", ".tbb", ".msi",
                ".scr", ".pif", ".hta", ".reg", ".js", ".vbe", ".wsf", ".cpl", ".cmd",
                ".vbs", ".jse", ".ws", ".wsc", ".ps1", ".ps1xml", ".ps2", ".psc1",
                ".psc2", ".msh", ".msh1", ".msh2", ".mshxml", ".msh1xml", ".msh2xml",
                ".scf", ".lnk", ".inf", ".reg")):
                arquivo_sha256 = hashlib.sha256()
                with open(file_path, "rb") as f:
                    for pedaco in iter(lambda: f.read(4096), b""):
                        arquivo_sha256.update(pedaco)

                return arquivo_sha256.hexdigest() in self.virus_hashes
        except OSError:
            pass

        return False

    def scan_drive(self):
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

        for root, _, files in os.walk(drive_path):
            for file in files:
                file_path = os.path.join(root, file)
                if self.check_for_virus(file_path):
                    arquivos_infectados.append(file_path)
                    try:
                        os.remove(file_path)
                        self.result_output.append(f"Arquivo infectado removido: {file_path}")
                    except OSError as e:
                        self.result_output.append(f"Erro ao remover o arquivo {file_path}: {e}")

                self.progress_bar.setValue(self.progress_bar.value() + 1)

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


    def run_sfc(self):
        try:
            # Executa o comando "sfc /scannow" como administrador
            cmd = "sfc /scannow"
            subprocess.run(["runas", "/user:Administrator", cmd], shell=True, text=True)

            self.result_output.append("Comando sfc /scannow iniciado como administrador.")
        except Exception as e:
            self.result_output.append(f"Erro ao executar sfc /scannow: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = VirusScannerApp()
    window.show()
    sys.exit(app.exec_())
