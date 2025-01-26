import socket
import threading
import rsa
import json

HOST = '127.0.0.1'
PORT = 1234
LISTENER_LIMIT = 5
active_clients = []

(server_public_key, server_private_key) = rsa.newkeys(1024)

def client_handler(client):
    client.sendall(server_public_key.save_pkcs1())
    while True:
        encrypted_username = client.recv(4096)
        client_public_key_pem = client.recv(4096)
        if encrypted_username:
            username = rsa.decrypt(encrypted_username, server_private_key).decode('utf-8')
            client_public_key = rsa.PublicKey.load_pkcs1(client_public_key_pem)
            active_clients.append((username, client, client_public_key))
            prompt_message = {"username": "SERVER", "message": f"{username} has joined the chat"}
            send_messages_to_clients(json.dumps(prompt_message), active_clients)
            break
        else:
            print("Client username is empty")
    threading.Thread(target=listen_for_messages, args=(client,)).start()

def listen_for_messages(client):
    while True:
        encrypted_message = client.recv(4096)
        if encrypted_message:
            try:
                decrypted_message = rsa.decrypt(encrypted_message, server_private_key).decode('utf-8')
                if(json.loads(decrypted_message)["message"].startswith("/whisper")==False):
                    send_messages_to_clients(decrypted_message, active_clients)
                else:
                    whisper_message = json.loads(decrypted_message)
                    whisper_targets = whisper_message["message"].split(" ")[1]+","+whisper_message["username"]
                    whisper_message["message"] = whisper_message["message"].split(" ", 2)[2]
                    dest_clients = []
                    for target in whisper_targets.split(","):
                        dest_client = get_client_by_username(target)
                        if dest_client:
                            dest_clients.append(dest_client)
                        else:
                            print(f"Client {target} not found.")
                    send_messages_to_clients(json.dumps(whisper_message), dest_clients)
            except rsa.pkcs1.DecryptionError:
              ("Failed to decrypt the message. The encrypted data or private key might be invalid.")
        else:
            print(f"{client}'s message is empty")

def send_message_to_client(client, message, client_public_key):
    encrypted_message = rsa.encrypt(message.encode('utf-8'), client_public_key)
    client.sendall(encrypted_message)
           
def send_messages_to_clients(message, clients):
    for user in clients:
        send_message_to_client(user[1], message, user[2])

def get_client_by_username(username):
    result = next((client for client in active_clients if client[0] == username), None)
    if result:
        return result
    else:
        return None


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((HOST, PORT))
        print(f"Running the server on {HOST}:{PORT}")
    except:
        print(f"Unable to bind to host {HOST} and port {PORT}")
    server.listen(LISTENER_LIMIT)
    while True:
        client, address = server.accept()
        print(f"Successfully connected to client {address[0]}:{address[1]}")
        threading.Thread(target=client_handler, args=(client,)).start()

if __name__ == '__main__':
    main()