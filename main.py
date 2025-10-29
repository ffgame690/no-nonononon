import socket
import threading
import struct

# إعدادات SOCKS Proxy
SOCKS_USERNAME = "tmk"
SOCKS_PASSWORD = "tmk"
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 3000

# إعدادات الفلتر
GAME_SERVER_PORT = 39699
BLOCKED_PACKET_PREFIX = b'\x06\x00'  # 0600 في hex

class PacketFilter:
    def __init__(self):
        self.blocked_count = 0
        self.total_packets = 0
    
    def should_block_packet(self, data, src_port):
        """فحص إذا كان يجب حظر الـ packet"""
        if not data or len(data) < 2:
            return False
        
        # فحص إذا كان الـ packet من port السرفر
        if src_port == GAME_SERVER_PORT:
            # فحص إذا كان الـ packet يبدأ بـ 0600
            if data[:2] == BLOCKED_PACKET_PREFIX:
                self.blocked_count += 1
                return True
        
        return False

class SOCKSProxy:
    def __init__(self):
        self.filter = PacketFilter()
        self.server_socket = None
    
    def start(self):
        """بدء الـ SOCKS proxy server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((PROXY_HOST, PROXY_PORT))
        self.server_socket.listen(5)
        
        try:
            while True:
                client_socket, addr = self.server_socket.accept()
                
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket,)
                )
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            self.stop()
    
    def handle_client(self, client_socket):
        """معالجة اتصال العميل"""
        try:
            # استقبال SOCKS handshake
            version = client_socket.recv(1)
            if version != b'\x05':
                client_socket.close()
                return
            
            # معالجة authentication methods
            nmethods = ord(client_socket.recv(1))
            methods = client_socket.recv(nmethods)
            
            # طلب username/password authentication
            client_socket.sendall(b'\x05\x02')
            
            # التحقق من credentials
            if not self.authenticate(client_socket):
                client_socket.close()
                return
            
            # استقبال الطلب
            version, cmd, _, atyp = struct.unpack('!BBBB', client_socket.recv(4))
            
            if cmd != 1:  # CONNECT command
                client_socket.close()
                return
            
            # الحصول على العنوان والـ port
            if atyp == 1:  # IPv4
                addr = socket.inet_ntoa(client_socket.recv(4))
            elif atyp == 3:  # Domain name
                addr_len = ord(client_socket.recv(1))
                addr = client_socket.recv(addr_len).decode()
            else:
                client_socket.close()
                return
            
            port = struct.unpack('!H', client_socket.recv(2))[0]
            
            # الاتصال بالسرفر المستهدف
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                remote_socket.connect((addr, port))
                
                # إرسال رد نجاح
                reply = b'\x05\x00\x00\x01' + socket.inet_aton('0.0.0.0') + struct.pack('!H', 0)
                client_socket.sendall(reply)
                
                # بدء تمرير البيانات مع الفلترة
                self.relay_data(client_socket, remote_socket, port)
                
            except:
                reply = b'\x05\x05\x00\x01' + socket.inet_aton('0.0.0.0') + struct.pack('!H', 0)
                client_socket.sendall(reply)
            finally:
                remote_socket.close()
                
        except:
            pass
        finally:
            client_socket.close()
    
    def authenticate(self, client_socket):
        """التحقق من username و password"""
        version = client_socket.recv(1)
        username_len = ord(client_socket.recv(1))
        username = client_socket.recv(username_len).decode()
        password_len = ord(client_socket.recv(1))
        password = client_socket.recv(password_len).decode()
        
        if username == SOCKS_USERNAME and password == SOCKS_PASSWORD:
            client_socket.sendall(b'\x01\x00')
            return True
        else:
            client_socket.sendall(b'\x01\x01')
            return False
    
    def relay_data(self, client_socket, remote_socket, remote_port):
        """تمرير البيانات بين العميل والسرفر مع الفلترة"""
        
        def forward(src, dst, is_from_server=False):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    
                    self.filter.total_packets += 1
                    
                    # فلترة البيانات القادمة من السرفر
                    if is_from_server:
                        if self.filter.should_block_packet(data, remote_port):
                            # حظر الـ packet ولا نرسله للعميل
                            continue
                    
                    dst.sendall(data)
            except:
                pass
        
        # إنشاء threads للتمرير في الاتجاهين
        client_to_server = threading.Thread(
            target=forward,
            args=(client_socket, remote_socket, False)
        )
        server_to_client = threading.Thread(
            target=forward,
            args=(remote_socket, client_socket, True)
        )
        
        client_to_server.daemon = True
        server_to_client.daemon = True
        
        client_to_server.start()
        server_to_client.start()
        
        client_to_server.join()
        server_to_client.join()
    
    def stop(self):
        """إيقاف الـ proxy"""
        if self.server_socket:
            self.server_socket.close()

def start_bot():
    """الدالة الرئيسية لبدء البوت"""
    proxy = SOCKSProxy()
    proxy.start()

if __name__ == "__main__":
    start_bot()
