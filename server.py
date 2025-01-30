import socket
import threading
import rsa
import json
from pymongo import MongoClient
from datetime import datetime
import zlib

HOST = '127.0.0.1'
PORT = 1234
LISTENER_LIMIT = 5
active_clients = []

MONGO_URI = "mongodb+srv://ndvgill:4XJS6FDkGvkLhavG@messangerapp.75ujm.mongodb.net/"
mclient = MongoClient(MONGO_URI)
db = mclient["MessangerApp"]
messages_collection = db["messages"]
users_collection = db["users"]

(server_public_key, server_private_key) = rsa.newkeys(1024)

def client_handler(client):
    client.sendall(server_public_key.save_pkcs1())
    while True:
        encrypted_username = client.recv(4096)
        client_public_key_pem = client.recv(4096)
        if encrypted_username:
            username = rsa.decrypt(encrypted_username, server_private_key).decode('utf-8')
            client_public_key = rsa.PublicKey.load_pkcs1(client_public_key_pem)
            if not users_collection.find_one({"username":username}): 
                users_collection.insert_one({"username": username,
                                                "public_key": client_public_key.save_pkcs1().decode('utf-8')})
            active_clients.append((username, client, client_public_key))
            prompt_message = {"username": "SERVER", "message": f"{username} has joined the chat"}
            send_messages_to_clients(json.dumps(prompt_message), active_clients)
            break
        else:
            print("Client username is empty")
    threading.Thread(target=listen_for_messages, args=(client,)).start()

def listen_for_messages(client):
    while True:
        compressed_encrypted_message = client.recv(4096)
        if compressed_encrypted_message:
            try:
                encrypted_message = zlib.decompress(compressed_encrypted_message)
                decrypted_message = rsa.decrypt(encrypted_message, server_private_key).decode('utf-8')
                message_data = json.loads(decrypted_message)
                if message_data["message"].startswith("/history"):
                    username = message_data["username"]
                    history = messages_collection.find().sort("timestamp", -1).limit(4)
                    history_string = "\n".join([f"{msg['username']}: {msg['message']}" for msg in history])
                    send_message_to_client(
                        client,
                        json.dumps({"username": "SERVER", "message": history_string}),
                        get_client_by_username(username)[2]
                    )
                elif not message_data["message"].startswith("/whisper"):
                    send_messages_to_clients(decrypted_message, active_clients)
                else:
                    whisper_message = message_data
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
              print("Failed to decrypt the message. The encrypted data or private key might be invalid.")
            except zlib.error:
                print("Failed to decompress the message. The compressed data might be invalid.")
        else:
            print(f"{client}'s message is empty")

def send_message_to_client(client, message, client_public_key):
    try:
        encrypted_message = rsa.encrypt(message.encode('utf-8'), client_public_key)
        compressed_encrypted_message = zlib.compress(encrypted_message)
        client.sendall(compressed_encrypted_message)
    except Exception as e:
        print(f"Error sending message to client: {e}")
           
def send_messages_to_clients(message, clients):
    message_data = json.loads(message)
    username = message_data["username"]
    content = message_data["message"]
    messages_collection.insert_one({"username": username, "message": content, "timestamp": datetime.now().isoformat()})
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