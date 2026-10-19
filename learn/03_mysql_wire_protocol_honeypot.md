> **Update:** attribution is now by exact match of the full token ID encoded in the username (`svc_<24 hex>`). The previous truncated `canary_<12>` username never matched and connections fell back to an arbitrary recent MySQL token. Packets are capped at 64 KiB before allocation, connections are limited, and client attributes (`_client_name`, `_client_version`...) plus planted-password verification are recorded.

# 03 — MySQL Wire Protocol Honeypot

## Why a Custom Protocol Implementation?

Running a full MySQL daemon (mysqld) just to capture intruder login attempts has major drawbacks:
1. **Resource Heavy**: `mysqld` requires significant RAM and CPU.
2. **Attack Surface**: Real MySQL servers are vulnerable to buffer overflows, privilege escalation, and misconfiguration.
3. **Log Scraping**: Extracting failed logins requires parsing text logs or audit plugins.

Instead, our Canary daemon implements the binary **MySQL Client/Server Wire Protocol** natively in pure Go (`internal/token/generators/mysql`).

---

## MySQL Binary Packet Structure

Every MySQL protocol packet is framed by a **4-byte header**:

```text
+-----------------------+---------------+-------------------------+
| Payload Length (3B)   | Sequence ID   | Payload (N bytes)       |
| Little-Endian uint24  | uint8 (0,1..) | Binary protocol data    |
+-----------------------+---------------+-------------------------+
```

```go
func WritePacket(w io.Writer, seq uint8, payload []byte) error {
    header := make([]byte, 4)
    length := len(payload)
    header[0] = byte(length)
    header[1] = byte(length >> 8)
    header[2] = byte(length >> 16)
    header[3] = seq
    w.Write(header)
    w.Write(payload)
}
```

---

## The Handshake State Machine

```
   Client (mysql CLI / DBeaver)                Canary Honeypot Listener
               |                                           |
               | <------------- TCP SYN / ACK ------------> |
               |                                           |
               | <------ 1. HandshakeV10 (Seq 0) -------- |
               |                                           |
               | ------- 2. HandshakeResponse41 (Seq 1) --> |
               |                                           | (Extracts: IP, username,
               |                                           |  database, client attributes)
               |                                           | (Dispatches Canary Alert)
               |                                           |
               | <------ 3. ERR_Packet (Seq 2) ----------- |
               |        (1045 Access Denied)               |
               v                                           v
         [Connection Closed]                       [Alert Sent to SOC]
```

---

## 1. Initial Handshake Packet (`Protocol::HandshakeV10`)

When a client opens a TCP socket to port 3306, the server speaks first by transmitting `HandshakeV10`:

| Field | Size | Description |
|---|---|---|
| Protocol Version | 1 byte | `0x0A` (Protocol 10) |
| Server Version | String | Null-terminated string (e.g. `8.0.35-canary-audit\x00`) |
| Thread ID | 4 bytes | uint32 connection counter |
| Auth Plugin Data Part 1 | 8 bytes | Random salt bytes |
| Filler | 1 byte | `0x00` |
| Capability Flags (Lower) | 2 bytes | Server capabilities (e.g. `0xf7df`) |
| Character Set | 1 byte | `0x21` (`utf8_general_ci`) |
| Status Flags | 2 bytes | `0x0002` (`SERVER_STATUS_AUTOCOMMIT`) |
| Capability Flags (Upper) | 2 bytes | `0x8180` (Supports auth plugins & client attrs) |
| Auth Data Len | 1 byte | Salt length (usually 21) |
| Reserved | 10 bytes | Null bytes |
| Auth Plugin Data Part 2 | 12 bytes | Remaining salt bytes + `0x00` |
| Auth Plugin Name | String | `mysql_native_password\x00` |

---

## 2. Parsing the Client Response (`HandshakeResponse41`)

The client answers with capability flags, followed by:
- Username: Null-terminated string.
- Scramble buffer (password hash).
- Database name (if `CLIENT_CONNECT_WITH_DB` capability was sent).
- Client attributes: Key-value map describing the attacker's client (e.g. `_client_name=libmysql`, `_os=Linux`, `_pid=4291`).

Our handler intercepts this packet and extracts the attacker's credentials without computing password hashes:
```go
auth, err := ParseHandshakeResponse41(respPayload)
// auth.Username: "canary_user_9a2b"
// auth.Database: "customer_vault"
```

---

## 3. Emulating Access Denied (`ERR_Packet`)

To make the attacker believe they reached a real database with incorrect or expired credentials, the server responds with a standard MySQL `ERR_Packet`:

- Header byte: `0xFF`
- Error Code: `1045` (`0x15, 0x04`) — `ER_ACCESS_DENIED_ERROR`
- SQL State Marker: `#` (`0x23`)
- SQL State: `28000`
- Message: `Access denied for user 'canary_user'@'203.0.113.19' (using password: YES)`

The attacker receives standard MySQL CLI output:
```text
$ mysql -h 198.51.100.2 -u root -p
Enter password: 
ERROR 1045 (28000): Access denied for user 'root'@'203.0.113.19' (using password: YES)
```
While the attacker believes their exploit failed, the defender has already received a high-priority alert with their IP address, client version, and username attempted!
