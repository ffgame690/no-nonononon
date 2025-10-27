import socket
import select
import threading
import time
from collections import deque

SOCKS_VERSION = 5

# نظام حظر سريع جداً
blocked_packets = set()
packet_times = {}
lock = threading.Lock()
MAX_REPEATS = 3  # خفضنا العدد لحظر أسرع
TIME_WINDOW = 1.5  # نافذة أصغر

class Proxy:
    def __init__(self):
        self.username = "tmk"
        self.password = "tmk"

    def check_spam(self, packet_hex):
        """فحص فائق السرعة للـ spam"""
        if not packet_hex.startswith("0600"):
            return False
        
        # فحص سريع للقائمة السوداء
        if packet_hex in blocked_packets:
            return True
        
        now = time.time()
        
        # استخدام deque للأداء الأفضل
        with lock:
            if packet_hex not in packet_times:
                packet_times[packet_hex] = deque(maxlen=MAX_REPEATS + 1)
            
            times = packet_times[packet_hex]
            
            # حذف الأوقات القديمة
            while times and now - times[0] > TIME_WINDOW:
                times.popleft()
            
            times.append(now)
            
            # حظر فوري
            if len(times) > MAX_REPEATS:
                blocked_packets.add(packet_hex)
                return True
        
        return False

    def handle_client(self, connection):
        try:
            version, nmethods = connection.recv(2)
            if not version or not nmethods:
                connection.close()
                return
                
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
            else:
                connection.close()
                return
            
            port = int.from_bytes(connection.recv(2), 'big', signed=False)
            
            if cmd != 1:
                connection.close()
                return
            
            try:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                remote.settimeout(5)
                remote.connect((address, port))
                bind_address = remote.getsockname()
            except:
                reply = self.generate_failed_reply(address_type, 5)
                connection.sendall(reply)
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
            
            connection.sendall(reply)
            self.exchange_loop(connection, remote)
            
        except:
            pass
        finally:
            try:
                connection.close()
            except:
                pass

    def exchange_loop(self, client, remote):
        try:
            # إعدادات للسرعة القصوى
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            client.setblocking(0)
            remote.setblocking(0)
            
            while True:
                try:
                    r, _, _ = select.select([client, remote], [], [], 0.5)
                except:
                    break

                if client in r:
                    try:
                        data = client.recv(16384)
                        if not data:
                            break
                        remote.sendall(data)
                    except BlockingIOError:
                        continue
                    except:
                        break

                if remote in r:
                    try:
                        data = remote.recv(16384)
                        if not data:
                            break
                        
                        # فحص سريع جداً
                        if data and self.check_spam(data.hex()):
                            continue
                        
                        client.sendall(data)
                    except BlockingIOError:
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

            response = bytes([version, 0])
            connection.sendall(response)
            
            if username == self.username and password == self.password:
                return True
            return True
        except:
            return False

    def get_available_methods(self, nmethods, connection):
        try:
            return [connection.recv(1)[0] for _ in range(nmethods)]
        except:
            return []

    def run(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.bind((ip, port))
            s.listen(500)
            
            while True:
                try:
                    conn, _ = s.accept()
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    t = threading.Thread(target=self.handle_client, args=(conn,), daemon=True)
                    t.start()
                except KeyboardInterrupt:
                    break
                except:
                    continue
        except:
            pass

def cleanup_worker():
    """تنظيف سريع كل 3 ثواني"""
    while True:
        time.sleep(3)
        try:
            now = time.time()
            with lock:
                for pkt in list(packet_times.keys()):
                    times = packet_times[pkt]
                    while times and now - times[0] > TIME_WINDOW:
                        times.popleft()
                    if not times:
                        del packet_times[pkt]
        except:
            pass

def start_bot():
    proxy = Proxy()
    threading.Thread(target=cleanup_worker, daemon=True).start()
    proxy.run("127.0.0.1", 3000)

if __name__ == "__main__":
    start_bot()
