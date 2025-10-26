import socket
import threading
import select
import time

SOCKS5_VERSION = 5
username = "1"
password = "1"
blocked_packets = set()
block_lock = threading.Lock()

spam_detector = {}
MAX_REPEATS = 5
WINDOW_TIME = 3  # ثانيتين فقط

def handle_client(connection):
    try:
        version, nmethods = connection.recv(2)
        methods = get_available_methods(connection, nmethods)
        if 2 not in set(methods):
            connection.close()
            return
        connection.sendall(bytes([SOCKS5_VERSION, 2]))
        if not verify(connection):
            return
        version, cmd, _, address_type = connection.recv(4)
        if address_type == 1:
            address = socket.inet_ntoa(connection.recv(4))
        elif address_type == 3:
            domain_length = connection.recv(1)[0]
            address = connection.recv(domain_length).decode('utf-8')
            address = socket.gethostbyname(address)
        port = int.from_bytes(connection.recv(2), 'big', signed=False)
        
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect((address, port))
        bind_address = remote.getsockname()
        addr = int.from_bytes(socket.inet_aton(bind_address[0]), 'big', signed=False)
        port = bind_address[1]
        reply = b"".join([
            SOCKS5_VERSION.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            int(1).to_bytes(1, 'big'),
            addr.to_bytes(4, 'big'),
            port.to_bytes(2, 'big')
        ])
        connection.sendall(reply)
        exchange_loop(connection, remote)
    except:
        pass

def verify(connection):
    version = connection.recv(1)[0]
    username_len = connection.recv(1)[0]
    username_received = connection.recv(username_len).decode('utf-8')
    password_len = connection.recv(1)[0]
    password_received = connection.recv(password_len).decode('utf-8')
    if username_received == username and password_received == password:
        connection.sendall(bytes([version, 0]))
        return True
    connection.sendall(bytes([version, 0xFF]))
    connection.close()
    return False

def get_available_methods(connection, nmethods):
    return [connection.recv(1)[0] for _ in range(nmethods)]

def is_spam(packet_hex):
    """كشف سريع للـ spam وإضافة فورية للقائمة السوداء"""
    # تحقق فقط من packets التي تبدأ بـ 0600
    if not packet_hex.startswith("0600"):
        return False
    
    # فحص القائمة السوداء أولاً (سريع جداً)
    if packet_hex in blocked_packets:
        return True
    
    current_time = time.time()
    
    # تنظيف البيانات القديمة
    if packet_hex in spam_detector:
        times = spam_detector[packet_hex]
        # حذف الأوقات القديمة
        spam_detector[packet_hex] = [t for t in times if current_time - t < WINDOW_TIME]
    else:
        spam_detector[packet_hex] = []
    
    # إضافة الوقت الحالي
    spam_detector[packet_hex].append(current_time)
    
    # إذا تكرر أكثر من الحد المسموح
    if len(spam_detector[packet_hex]) > MAX_REPEATS:
        with block_lock:
            blocked_packets.add(packet_hex)
        print(f"\n🚫 SPAM DETECTED & BLOCKED!")
        print(f"📦 Packet: {packet_hex[:40]}...")
        print(f"🔒 Permanently filtered from all traffic\n")
        return True
    
    return False

def exchange_loop(client, remote):
    try:
        while True:
            r, _, _ = select.select([client, remote], [], [], 0.5)
            
            if client in r:
                data = client.recv(8192)  # buffer أكبر
                if not data:
                    break
                if remote.send(data) <= 0:
                    break
            
            if remote in r:
                data = remote.recv(8192)  # buffer أكبر
                if not data:
                    break
                
                # فحص سريع جداً
                packet_hex = data.hex()
                if is_spam(packet_hex):
                    # حظر فوري - لا ترسل للعميل
                    continue
                
                if client.send(data) <= 0:
                    break
    except:
        pass
    finally:
        try:
            client.close()
            remote.close()
        except:
            pass

def cleanup_thread():
    """تنظيف دوري للبيانات القديمة"""
    while True:
        time.sleep(5)
        current_time = time.time()
        # تنظيف spam_detector
        for packet in list(spam_detector.keys()):
            spam_detector[packet] = [t for t in spam_detector[packet] 
                                    if current_time - t < WINDOW_TIME]
            if not spam_detector[packet]:
                del spam_detector[packet]

def run(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(100)  # queue أكبر
    print(f"🔒 High-Performance Proxy running on: {host}:{port}")
    print(f"⚡ Fast spam filter active")
    print(f"🛡️  Auto-blocking spam packets (>{MAX_REPEATS} times in {WINDOW_TIME}s)\n")
    
    # Thread للتنظيف
    cleaner = threading.Thread(target=cleanup_thread, daemon=True)
    cleaner.start()
    
    while True:
        try:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn,), daemon=True)
            t.start()
        except:
            pass

if __name__ == "__main__":
    run("127.0.0.1", 3000)
