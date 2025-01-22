import socket
import threading
import rsa
import json

HOST = '127.0.0.1'
PORT = 1234
LISTENER_LIMIT = 5
active_clients = []

(public_key, private_key) = rsa.newkeys(1024)

def client_handler(client):
    client.sendall(public_key.save_pkcs1())
    while True:
        encrypted_username = client.recv(4096)
        if encrypted_username:
            username = rsa.decrypt(encrypted_username, private_key).decode('utf-8')
            active_clients.append((username, client))
            prompt_message = {"username": "SERVER", "message": f"{username} has joined the chat"}
            send_messages_to_all(json.dumps(prompt_message))
            break
        else:
            print("Client username is empty")
    threading.Thread(target=listen_for_messages, args=(client, username)).start()

def listen_for_messages(client, username):
    while True:
        encrypted_message = client.recv(4096)
        if encrypted_message:
            try:
                decrypted_message = rsa.decrypt(encrypted_message, private_key).decode('utf-8')
                message_data = json.loads(decrypted_message)
                final_msg = {"username": username, "message": message_data["message"]}
                send_messages_to_all(json.dumps(final_msg))
            except rsa.pkcs1.DecryptionError:
              print("Failed to decrypt the message. The encrypted data or private key might be invalid.")
            except json.JSONDecodeError:
                 print("The decrypted message is not valid JSON.")
            except KeyError:
                  print("The JSON message does not contain the expected key 'message'.")
        else:
            print(f"{client}'s message is empty")

def send_message_to_client(client, message):
    client.sendall(message.encode('utf-8'))
           
def send_messages_to_all(message):
    for user in active_clients:
        send_message_to_client(user[1], message)


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