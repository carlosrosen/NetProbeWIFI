class Device:
    def __init__(self, ip, mac=None):
        self.ip = ip
        self.mac = mac
        self.status = "online"
        self.open_ports = []