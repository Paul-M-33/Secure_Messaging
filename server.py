import asyncio
import json
import websockets

# Store connected clients: dict of : name → dict of : (websocket, public key)
clients = {}


async def handler(ws):
    """
    Handle the lifecycle of a single client connection.

    This function is called for each client that connects to the server.
    It listens for incoming messages from the client and handles:
        - Registration
        - Requests for peer lists
        - Message forwarding
        - Disconnection

    Parameters:
        ws (websockets.WebSocketServerProtocol): The WebSocket connection for this client.

    Behavior:
        - Registers the user and stores their WebSocket and public key.
        - Forwards messages to other connected clients.
        - Sends errors if the recipient is not online.
        - Cleans up client data upon disconnection.
    """
    name = None
    try:
        async for raw in ws:
            msg = json.loads(raw)
            t = msg.get("type")

            # Register the username
            if t == "register":
                name = msg["name"]
                clients[name] = {"ws": ws, "pub_key": msg["pub_key"]}
                print(f"[CONNECT] {name}")
                await broadcast_peers()

            # Client asks for peer list
            elif t == "get_peers":
                await send_peers(ws)

            # Forward a message to another user
            elif t == "send":
                to = msg["to"]
                payload = msg["payload"]
                sender = msg["from"]

                if to in clients:
                    out = {
                        "type": "forward",
                        "from": sender,
                        "payload": payload,
                    }

                    if "signature" in msg:
                        out["signature"] = msg["signature"]

                    await clients[to]["ws"].send(json.dumps(out))
                    print(f"[FORWARD] {sender} → {to}: {payload}")
                else:
                    await ws.send(json.dumps({"type": "error", "message": f"{to} not online"}))

            elif t == "aes_key":
                # forward same structure to receiver
                sender = msg["from"]
                to = msg["to"]
                encrypted_key = msg["payload"]

                print(f"[AES_KEY_CIPHERED] {sender} → {to}: {encrypted_key}")

                # Build the forwarded packet
                out = {
                    "type": "aes_key",
                    "from": sender,
                    "to": to,
                    "payload": encrypted_key
                }

                await clients[to]["ws"].send(json.dumps(out))

    except websockets.ConnectionClosed:
        pass

    finally:
        if name and name in clients and clients[name] is ws:
            del clients[name]
            print(f"[DISCONNECT] {name}")
            await broadcast_peers()


# Send the list of connected users to one client
async def send_peers(ws):
    """
    Send the current list of connected users and their public keys to a single client.

    Parameters:
        ws (websockets.WebSocketServerProtocol): The WebSocket connection of the recipient client.

    Sends:
        JSON object containing:
            - "type": "peers"
            - "peers": list of usernames currently connected
            - "pubkeys": dictionary mapping username → public key
    """
    await ws.send(json.dumps({
        "type": "peers",
        "peers": list(clients.keys()),
        "pubkeys": {name: info["pub_key"] for name, info in clients.items()}
    }))


# Send the list of connected users to everyone
async def broadcast_peers():
    """
    Broadcast the current list of connected users and their public keys to all clients.

    Sends to every connected client:
        JSON object containing:
            - "type": "peers"
            - "peers": list of usernames currently connected
            - "pubkeys": dictionary mapping username → public key

    Uses asyncio.gather to send messages concurrently.
    """
    data = json.dumps({
        "type": "peers",
        "peers": list(clients.keys()),
        "pubkeys": {name: info["pub_key"] for name, info in clients.items()}
    })
    await asyncio.gather(
        *(info["ws"].send(data) for info in clients.values()),
        return_exceptions=True
    )


async def main():
    """
    Start the WebSocket server and run it indefinitely.

    - Binds the server to 0.0.0.0:8765
    - Uses the 'handler' function for each new client connection
    - Keeps the server running forever
    """
    print("Server running at ws://localhost:8765")
    async with websockets.serve(handler, "0.0.0.0", 8765):
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
