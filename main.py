import socket
import select
import threading
import time

SOCKS_VERSION = 5

# نظام حظر الـ spam
blocked_packets = set()
spam_detector = {}
MAX_REPEATS = 5
WINDOW_TIME = 2

class Proxy:
    def __init__(self):
        self.username = "tmk"
        self.password = "tmk"

    def is_spam(self, packet_hex):
        """كشف سريع للـ spam"""
        if not packet_hex.startswith("0600"):
            return False
        
        if packet_hex in blocked_packets:
            return True
        
        current_time = time.time()
        
        if packet_hex in spam_detector:
            times = spam_detector[packet_hex]
            spam_detector[packet_hex] = [t for t in times if current_time - t < WINDOW_TIME]
        else:
            spam_detector[packet_hex] = []
        
        spam_detector[packet_hex].append(current_time)
        
        if len(spam_detector[packet_hex]) > MAX_REPEATS:
            blocked_packets.add(packet_hex)
            return True
        
        return False

    def handle_client(self, connection):
        try:
            version, nmethods = connection.recv(2)
            methods = self.get_available_methods(nmethods, connection)
            if 2 not in set(methods):
                connection.close()
                return
            connection.sendall(bytes([SOCKS_VERSION, 2]))
            if not self.verify_credentials(connection):
                return
            version, cmd, _, address_type = connection.recv(4)
            if address_type == 1:
                address = socket.inet_ntoa(connection.recv(4))
            elif address_type == 3:
                domain_length = connection.recv(1)[0]
                address = connection.recv(domain_length)
                try:
                    address = socket.gethostbyname(address)
                except:
                    connection.close()
                    return
            
            port = int.from_bytes(connection.recv(2), 'big', signed=False)
            
            try:
                if cmd == 1:
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote.settimeout(10)
                    remote.connect((address, port))
                    bind_address = remote.getsockname()
                else:
                    connection.close()
                    return
                
                addr = int.from_bytes(socket.inet_aton(bind_address[0]), 'big', signed=False)
                port = bind_address[1]
                reply = b''.join([
                    SOCKS_VERSION.to_bytes(1, 'big'),
                    int(0).to_bytes(1, 'big'),
                    int(0).to_bytes(1, 'big'),
                    int(1).to_bytes(1, 'big'),
                    addr.to_bytes(4, 'big'),
                    port.to_bytes(2, 'big')
                ])
            except Exception as e:
                reply = self.generate_failed_reply(address_type, 5)
            
            connection.sendall(reply)
            if reply[1] == 0 and cmd == 1:
                self.exchange_loop(connection, remote)
            connection.close()
        except:
            try:
                connection.close()
            except:
                pass

    def exchange_loop(self, client, remote):
        try:
            client.settimeout(0.1)
            remote.settimeout(0.1)
            
            while True:
                try:
                    r, w, e = select.select([client, remote], [], [], 1)
                except:
                    break

                if client in r:
                    try:
                        dataC = client.recv(8192)
                        if not dataC:
                            break
                        remote.sendall(dataC)
                    except socket.timeout:
                        continue
                    except:
                        break

                if remote in r:
                    try:
                        data = remote.recv(8192)
                        if not data:
                            break
                        
                        # فحص الـ spam فقط
                        packet_hex = data.hex()
                        if self.is_spam(packet_hex):
                            continue
                        
                        client.sendall(data)
                    except socket.timeout:
                        continue
                    except:
                        break
        except:
            pass
        finally:
            try:
                client.close()
            except:
                pass
            try:
                remote.close()
            except:
                pass

    def generate_failed_reply(self, address_type, error_number):
        return b''.join([
            SOCKS_VERSION.to_bytes(1, 'big'),
            error_number.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            address_type.to_bytes(1, 'big'),
            int(0).to_bytes(4, 'big'),
            int(0).to_bytes(4, 'big')
        ])

    def verify_credentials(self, connection):
        try:
            version = connection.recv(1)[0]
            username_len = connection.recv(1)[0]
            username = connection.recv(username_len).decode('utf-8')
            password_len = connection.recv(1)[0]
            password = connection.recv(password_len).decode('utf-8')

            if username == self.username and password == self.password:
                response = bytes([version, 0])
                connection.sendall(response)
                return True
            else:
                response = bytes([version, 0])
                connection.sendall(response)
                return True
        except:
            try:
                connection.close()
            except:
                pass
            return False

    def get_available_methods(self, nmethods, connection):
        try:
            methods = []
            for _ in range(nmethods):
                methods.append(connection.recv(1)[0])
            return methods
        except:
            return []

    def run(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((ip, port))
            s.listen(200)
            
            while True:
                try:
                    conn, addr = s.accept()
                    t = threading.Thread(target=self.handle_client, args=(conn,), daemon=True)
                    t.start()
                except KeyboardInterrupt:
                    break
                except:
                    continue
        except:
            pass
        finally:
            try:
                s.close()
            except:
                pass

def cleanup_thread():
    """تنظيف دوري للبيانات القديمة"""
    while True:
        time.sleep(10)
        try:
            current_time = time.time()
            for packet in list(spam_detector.keys()):
                spam_detector[packet] = [t for t in spam_detector[packet] 
                                        if current_time - t < WINDOW_TIME]
                if not spam_detector[packet]:
                    del spam_detector[packet]
        except:
            pass

def start_bot():
    proxy = Proxy()
    cleaner = threading.Thread(target=cleanup_thread, daemon=True)
    cleaner.start()
    proxy.run("127.0.0.1", 3000)

if __name__ == "__main__":
    start_bot()
