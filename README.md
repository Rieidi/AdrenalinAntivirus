
# PyAV
PyAV is an antivirus developed entirely in Python. It features a daily hash update function using the Malware-Basar API.

## Features

- Daily hash updates
- System tray icon to restore or exit the application
- Window hidden when closed, keeping the application running
- Hourly hash updates

## How to Use

1. **Clone the repository:**

   ```bash
   git clone https://github.com/Rieidi/PyAV.git
   ```

2. **Navigate to the project directory:**

   ```bash
   cd PyAV
   ```

3. **Install the required dependencies:**

   Make sure you have Python installed. Then, install the dependencies listed in the `requirements.txt` file:

   ```bash
   pip install -r requirements.txt
   ```

4. **Set up the Malware-Basar API:**

   Place the necessary `.txt` file in the same directory as the main `.py` file, as mentioned in the repository.

5. **Run the antivirus:**

   ```bash
   python PyAV.py
   ```

## Upcoming Updates

- Botloader backup
- Web protection

## License

MIT LICENSE 
