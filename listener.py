# listener.py — run in a separate terminal
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0)) 
port = s.getsockname()[1]
print(f"Listening on 127.0.0.1:{port}")
s.listen(1)
input("Press Enter to close...")
s.close()