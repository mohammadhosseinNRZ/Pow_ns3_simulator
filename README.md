# 🔗 NS-3 Blockchain Node Simulation (NodeApp)

This project implements a simulated blockchain node using the **NS-3 network simulator**. Each node can **mine**, **broadcast**, **validate**, and **store blocks**, communicating via UDP sockets. The project is designed to model **decentralized ledger behavior**, including fork resolution and peer-to-peer communication.

---

## 🚀 Features

- 🧱 **Block Creation & Mining**  
  Each node can create blocks with contents, timestamps, and nonces. Blocks are mined using a simplified **proof-of-work** (PoW) mechanism by searching for a valid hash containing a zero byte.

- 📡 **UDP-based Peer Communication**  
  Nodes communicate over UDP sockets, allowing for asynchronous message broadcasting and reception.

- 🔄 **Fork Handling & Longest Chain Resolution**  
  Nodes can handle forked blockchains by maintaining `list_of_ledgers`, and switching to the longest valid chain when a longer one is detected.

- 📬 **Message Serialization & Deserialization**  
  Blocks are serialized into strings using a custom format (`blockToString`) and parsed back (`stringToBlock`) during communication.

- ✅ **Validation**  
  Incoming blocks are validated via SHA-256 hash comparison and `previous_hash` checks.

---

## 📁 Files Overview

| File          | Purpose                                     |
|---------------|---------------------------------------------|
| `node-app.cc` | Core implementation of the blockchain node  |
| `node-app.h`  | Class declarations and block structures     |
| `sha-256.h`   | SHA-256 hash function header (external dep) |

---

## 🧩 Key Components

### `block_header_t` (Struct)
Represents a block header containing:
- `contents_length`, `contents_hash`
- `previous_hash`, `timestamp`, `nonce`
- `block_number`

---

### Core Methods (NodeApp)
| Method               | Description                                  |
|----------------------|----------------------------------------------|
| `StartApplication()` | Initializes sockets and peer connections     |
| `sendMessage()`      | Builds, mines, and broadcasts a new block    |
| `HandleRead()`       | Parses received messages and updates ledger  |
| `mine_block()`       | Performs proof-of-work mining                |
| `check_validation()` | Validates hash of a received block           |
| `SendTX()`           | Broadcasts a block to peer nodes             |
| `isPrevious()`       | Validates block continuity                   |

---

## 📡 Networking Model

- Each node listens on port `7071`.
- Nodes use `UdpSocketFactory` to connect to their peers.
- Broadcasting is done via `SendTX()`, scheduling messages with random delays.

---

## 🧪 Simulation Details

- Uses `NS_LOG_INFO` for console output (enable with `NS_LOG=NodeApp=level_info`)
- SHA-256 hash generation is based on external `sha-256.h` implementation (or OpenSSL SHA256 if included).
- Blocks are built using `build_block()` and formatted as strings for network transmission.

---

## 🛠 Requirements

- NS-3 (tested on ns-3.30+)
- C++11+
- SHA-256 library (`sha-256.h`) or OpenSSL
- Proper NS-3 environment and `waf` build system

---

## 🧠 Example Use Cases

- Simulate decentralized mining in NS-3
- Study fork handling in P2P networks
- Test block propagation and ledger sync over UDP
- Implement future extensions: consensus algorithms, malicious node behavior, etc.

---

## 📬 Contact

Feel free to fork, contribute, or integrate this into your NS-3 simulation workflows.  
Great base for research projects or teaching blockchain fundamentals in a networked simulation!

