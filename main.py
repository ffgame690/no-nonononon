import socket
import select
import threading
import time

SOCKS_VERSION = 5

# 🛡️ نظام دفاع متعدد الطبقات
GLOBAL_BLOCK = set()
RATE_LIMIT = {}
LOCK = threading.Lock()

# ⚙️ إعدادات الحماية القصوى
MAX_PACKETS_PER_SEC = 2
BLOCK_THRESHOLD = 3
DETECTION_WINDOW = 0.8
CLEANUP_INTERVAL = 1.5

class Proxy:
    def __init__(self):
        self.username = "tmk"
        self.password = "tmk"
    
    def detect_attack(self, hex_data):
        """🔍 كشف ذكي متعدد الطبقات للهجمات"""
        if hex_data in GLOBAL_BLOCK:
            return True
        
        if not hex_data.startswith("0600"):
            return False
        
        now = time.time()
        
        with LOCK:
            if hex_data not in RATE_LIMIT:
                RATE_LIMIT[hex_data] = []
            
            RATE_LIMIT[hex_data] = [
                t for t in RATE_LIMIT[hex_data] 
                if now - t < DETECTION_WINDOW
            ]
            
            RATE_LIMIT[hex_data].append(now)
            count = len(RATE_LIMIT[hex_data])
            
            if count > BLOCK_THRESHOLD:
                GLOBAL_BLOCK.add(hex_data)
                del RATE_LIMIT[hex_data]
                return True
            
            if count >= MAX_PACKETS_PER_SEC:
                time_span = now - RATE_LIMIT[hex_data][0]
                if time_span < 0.5:
                    GLOBAL_BLOCK.add(hex_data)
                    del RATE_LIMIT[hex_data]
                    return True
        
        return False

    def handle_client(self, conn):
        remote = None
        try:
            v, n = conn.recv(2)
            methods = [conn.recv(1)[0] for _ in range(n)]
            
            if 2 not in methods:
                conn.close()
                return
            
            conn.sendall(bytes([SOCKS_VERSION, 2]))
            
            v = conn.recv(1)[0]
            ulen = conn.recv(1)[0]
            user = conn.recv(ulen)
            plen = conn.recv(1)[0]
            pwd = conn.recv(plen)
            
            conn.sendall(bytes([v, 0]))
            
            v, cmd, _, atyp = conn.recv(4)
            
            if cmd != 1:
                conn.close()
                return
            
            if atyp == 1:
                addr = socket.inet_ntoa(conn.recv(4))
            elif atyp == 3:
                dlen = conn.recv(1)[0]
                addr = socket.gethostbyname(conn.recv(dlen))
            else:
                conn.close()
                return
            
            port = int.from_bytes(conn.recv(2), 'big')
            
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            remote.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            remote.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            remote.settimeout(3)
            remote.connect((addr, port))
            
            ba = remote.getsockname()
            reply = (
                SOCKS_VERSION.to_bytes(1, 'big') +
                b'\x00\x00\x01' +
                socket.inet_aton(ba[0]) +
                ba[1].to_bytes(2, 'big')
            )
            conn.sendall(reply)
            
            self.protected_exchange(conn, remote)
            
        except:
            pass
        finally:
            try:
                conn.close()
            except:
                pass
            try:
                if remote:
                    remote.close()
            except:
                pass

    def protected_exchange(self, client, remote):
        """🛡️ نقل بيانات محمي بالكامل"""
        try:
            client.setblocking(0)
            remote.setblocking(0)
            
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            
            blocked_count = 0
            
            while True:
                try:
                    r, _, _ = select.select([client, remote], [], [], 0.2)
                except:
                    break
                
                if client in r:
                    try:
                        data = client.recv(32768)
                        if not data:
                            break
                        remote.sendall(data)
                    except BlockingIOError:
                        pass
                    except:
                        break
                
                if remote in r:
                    try:
                        data = remote.recv(32768)
                        if not data:
                            break
                        
                        if self.detect_attack(data.hex()):
                            blocked_count += 1
                            if blocked_count > 50:
                                break
                            continue
                        
                        client.sendall(data)
                        
                    except BlockingIOError:
                        pass
                    except:
                        break
                        
        except:
            pass

    def run(self, host, port):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            try:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except:
                pass
            
            srv.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            srv.bind((host, port))
            srv.listen(2000)
            
            while True:
                try:
                    conn, _ = srv.accept()
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    threading.Thread(
                        target=self.handle_client, 
                        args=(conn,), 
                        daemon=True
                    ).start()
                except KeyboardInterrupt:
                    break
                except:
                    pass
        except:
            pass

def cleanup_worker():
    """🧹 تنظيف عدواني للذاكرة"""
    while True:
        time.sleep(CLEANUP_INTERVAL)
        try:
            now = time.time()
            with LOCK:
                for pkt in list(RATE_LIMIT.keys()):
                    RATE_LIMIT[pkt] = [
                        t for t in RATE_LIMIT[pkt] 
                        if now - t < DETECTION_WINDOW
                    ]
                    if not RATE_LIMIT[pkt]:
                        del RATE_LIMIT[pkt]
                
                if len(GLOBAL_BLOCK) > 1000:
                    items = list(GLOBAL_BLOCK)
                    GLOBAL_BLOCK.clear()
                    GLOBAL_BLOCK.update(items[-800:])
                    
        except:
            pass

def start_bot():
    proxy = Proxy()
    threading.Thread(target=cleanup_worker, daemon=True).start()
    proxy.run("127.0.0.1", 3000)

if __name__ == "__main__":
    start_bot()
