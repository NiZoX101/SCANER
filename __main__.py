from gui import CodeScannerGUI
from PyQt5.QtWidgets import QApplication
import sys

if __name__ == "__main__":
    app = QApplication(sys.argv)
    scanner_gui = CodeScannerGUI()
    scanner_gui.show()
    sys.exit(app.exec_())
