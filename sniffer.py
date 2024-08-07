import sys
import threading
import logging
from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
from PyQt5 import QtWidgets, QtGui, QtCore

# Set up logging
logging.basicConfig(level=logging.DEBUG)

class PacketDetailWindow(QtWidgets.QWidget):
    def __init__(self, packet_info):
        super().__init__()
        self.initUI(packet_info)

    def initUI(self, packet_info):
        self.setWindowTitle('Packet Details')
        self.setGeometry(200, 200, 600, 400)
        
        layout = QtWidgets.QVBoxLayout()
        
        for key, value in packet_info.items():
            layout.addWidget(QtWidgets.QLabel(f'{key}: {value}'))
        
        self.setLayout(layout)

class PacketSniffer(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()

        self.initUI()
        self.packets = []
        self.sniffing = False
        self.stop_event = threading.Event()

    def initUI(self):
        self.setWindowTitle('Packet Sniffer')
        self.setGeometry(100, 100, 1400, 800)

        # Layouts
        mainLayout = QtWidgets.QVBoxLayout()
        buttonLayout = QtWidgets.QHBoxLayout()
        tableLayout = QtWidgets.QVBoxLayout()
        filterLayout = QtWidgets.QHBoxLayout()

        # Buttons
        self.startButton = QtWidgets.QPushButton('Start Sniffing')
        self.stopButton = QtWidgets.QPushButton('Stop Sniffing')
        self.clearButton = QtWidgets.QPushButton('Clear')
        
        self.startButton.clicked.connect(self.startSniffing)
        self.stopButton.clicked.connect(self.stopSniffing)
        self.clearButton.clicked.connect(self.clearPackets)

        buttonLayout.addWidget(self.startButton)
        buttonLayout.addWidget(self.stopButton)
        buttonLayout.addWidget(self.clearButton)

        # Filter
        self.filterInput = QtWidgets.QLineEdit()
        self.filterInput.setPlaceholderText('Enter protocol filter (e.g., TCP, UDP, HTTP, ICMP)')
        self.filterButton = QtWidgets.QPushButton('Apply Filter')
        self.filterButton.clicked.connect(self.applyFilter)
        filterLayout.addWidget(self.filterInput)
        filterLayout.addWidget(self.filterButton)

        # Table
        self.packetTable = QtWidgets.QTableWidget()
        self.packetTable.setColumnCount(10)
        self.packetTable.setHorizontalHeaderLabels(['Time', 'Source', 'Source Port', 'Destination', 'Destination Port', 'Protocol', 'Length', 'Flags', 'Info', 'Additional Info'])
        self.packetTable.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.packetTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)  # Select entire row
        self.packetTable.cellClicked.connect(self.showPacketDetails)

        tableLayout.addLayout(filterLayout)
        tableLayout.addWidget(self.packetTable)

        mainLayout.addLayout(buttonLayout)
        mainLayout.addLayout(tableLayout)

        # Central widget
        centralWidget = QtWidgets.QWidget()
        centralWidget.setLayout(mainLayout)
        self.setCentralWidget(centralWidget)

        # Details section
        self.detailTextEdit = QtWidgets.QTextEdit()
        self.detailTextEdit.setReadOnly(True)
        tableLayout.addWidget(self.detailTextEdit)

    def startSniffing(self):
        self.sniffing = True
        self.stop_event.clear()
        self.sniffThread = threading.Thread(target=self.sniffPackets)
        self.sniffThread.start()

    def stopSniffing(self):
        self.sniffing = False
        self.stop_event.set()
        if hasattr(self, 'sniffThread'):
            self.sniffThread.join()

    def clearPackets(self):
        self.packetTable.setRowCount(0)
        self.packets = []

    def applyFilter(self):
        filter_protocol = self.filterInput.text().upper()
        self.packetTable.setRowCount(0)
        for packet in self.packets:
            if filter_protocol == "" or filter_protocol in packet['Protocol']:
                self.addPacketToTable(packet)

    def sniffPackets(self):
        def packetCallback(packet):
            if self.stop_event.is_set():
                return False

            proto, flags = self.identifyProtocol(packet)
            if proto is None:
                return

            packet_info = {
                'Time': pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S'),
                'Source': packet[IP].src if IP in packet else '',
                'Source Port': packet.sport if TCP in packet or UDP in packet else '',
                'Destination': packet[IP].dst if IP in packet else '',
                'Destination Port': packet.dport if TCP in packet or UDP in packet else '',
                'Protocol': proto,
                'Length': len(packet),
                'Flags': flags if flags else '',
                'Info': packet.summary(),
                'Additional Info': self.getAdditionalInfo(packet)
            }

            self.packets.append(packet_info)
            self.addPacketToTable(packet_info)
        
        sniff(prn=packetCallback, store=0, stop_filter=lambda x: self.stop_event.is_set())

    def identifyProtocol(self, packet):
        if IP in packet:
            if TCP in packet:
                flags = packet.sprintf('%TCP.flags%')
                if packet[TCP].sport == 80 or packet[TCP].dport == 80:
                    return 'HTTP', flags
                elif packet[TCP].sport == 443 or packet[TCP].dport == 443:
                    return 'HTTPS', flags
                else:
                    return 'TCP', flags
            elif UDP in packet:
                return 'UDP', None
            elif ICMP in packet:
                return 'ICMP', None
            else:
                return 'IP', None
        return None, None

    def getAdditionalInfo(self, packet):
        info = []
        if TCP in packet:
            info.append(f"Seq={packet[TCP].seq}")
            info.append(f"Ack={packet[TCP].ack}")
            info.append(f"Window={packet[TCP].window}")
        return ", ".join(info)

    def addPacketToTable(self, packet_info):
        rowPosition = self.packetTable.rowCount()
        self.packetTable.insertRow(rowPosition)
        self.packetTable.setItem(rowPosition, 0, QtWidgets.QTableWidgetItem(packet_info['Time']))
        self.packetTable.setItem(rowPosition, 1, QtWidgets.QTableWidgetItem(packet_info['Source']))
        self.packetTable.setItem(rowPosition, 2, QtWidgets.QTableWidgetItem(str(packet_info['Source Port'])))
        self.packetTable.setItem(rowPosition, 3, QtWidgets.QTableWidgetItem(packet_info['Destination']))
        self.packetTable.setItem(rowPosition, 4, QtWidgets.QTableWidgetItem(str(packet_info['Destination Port'])))
        self.packetTable.setItem(rowPosition, 5, QtWidgets.QTableWidgetItem(packet_info['Protocol']))
        self.packetTable.setItem(rowPosition, 6, QtWidgets.QTableWidgetItem(str(packet_info['Length'])))
        self.packetTable.setItem(rowPosition, 7, QtWidgets.QTableWidgetItem(packet_info['Flags']))
        self.packetTable.setItem(rowPosition, 8, QtWidgets.QTableWidgetItem(packet_info['Info']))
        self.packetTable.setItem(rowPosition, 9, QtWidgets.QTableWidgetItem(packet_info['Additional Info']))

        for i in range(self.packetTable.columnCount()):
            self.packetTable.item(rowPosition, i).setBackground(self.getColorForProtocol(packet_info['Protocol']))

    def getColorForProtocol(self, protocol):
        if protocol == 'TCP':
            return QtGui.QColor(255, 182, 193)  # Light Pink
        elif protocol == 'UDP':
            return QtGui.QColor(173, 216, 230)  # Light Blue
        elif protocol == 'HTTP':
            return QtGui.QColor(144, 238, 144)  # Light Green
        elif protocol == 'HTTPS':
            return QtGui.QColor(255, 228, 181)  # Moccasin
        elif protocol == 'ICMP':
            return QtGui.QColor(255, 250, 205)  # LemonChiffon
        elif protocol == 'IP':
            return QtGui.QColor(240, 255, 240)  # Honeydew
        else:
            return QtGui.QColor(211, 211, 211)  # LightGray

    def showPacketDetails(self, row, column):
        self.packetTable.selectRow(row)  # Select the entire row
        packet_info = self.packets[row]
        details = '\n'.join([f'{key}: {value}' for key, value in packet_info.items()])
        self.detailTextEdit.setPlainText(details)

    def closeEvent(self, event):
        self.stopSniffing()
        event.accept()

def main():
    app = QtWidgets.QApplication(sys.argv) 
    window = PacketSniffer()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
