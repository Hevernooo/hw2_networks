import socket
import struct
import threading
import json
import time
import os
from dataclasses import dataclass


ROOT_SERVER = '198.41.0.4'
CACHE_FILE = 'dns_cache.json'
LISTEN_IP = '127.0.0.1'
LISTEN_PORT = 53


def parse_domain_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumped = False
    original_offset = offset

    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            pointer_offset = ((length & 0x3F) << 8) | data[offset + 1]
            offset = pointer_offset
            jumped = True
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode('utf-8'))
            offset += length

    return ".".join(labels), (original_offset if jumped else offset)


def pack_domain_name(domain: str) -> bytes:
    if domain == "." or not domain:
        return b"\x00"
    return b"".join(struct.pack('!B', len(p)) + p.encode('utf-8') for p in domain.split(".")) + b"\x00"


@dataclass
class DNSHeader:
    tx_id: int
    flags: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int

    @classmethod
    def from_bytes(cls, data: bytes) -> 'DNSHeader':
        return cls(*struct.unpack('!HHHHHH', data[:12]))


@dataclass
class DNSQuestion:
    name: str
    qtype: int
    qclass: int

    @classmethod
    def from_bytes(cls, data: bytes, offset: int) -> tuple['DNSQuestion', int]:
        name, offset = parse_domain_name(data, offset)
        qtype, qclass = struct.unpack('!HH', data[offset:offset + 4])
        return cls(name, qtype, qclass), offset + 4


@dataclass
class DNSRecord:
    rtype: int
    rclass: int
    ttl: int
    rdlength: int
    rdata: bytes

    @classmethod
    def from_bytes(cls, data: bytes, offset: int) -> tuple['DNSRecord', int]:
        _, offset = parse_domain_name(data, offset)  # Пропускаем имя
        rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        return cls(rtype, rclass, ttl, rdlength, rdata), offset + rdlength


cache: dict[tuple[str, int], tuple[float, str]] = {}


def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                raw_cache = json.load(f)
                for key_str, (expiry, hex_data) in raw_cache.items():
                    if time.time() < expiry:
                        domain, qtype = key_str.rsplit(":", 1)
                        cache[(domain, int(qtype))] = (expiry, hex_data)
            print(f"[CACHE] Загружено {len(cache)} актуальных записей.")
        except Exception as e:
            print(f"[CACHE] Ошибка загрузки: {e}")


def save_cache():
    current = time.time()
    clean_cache = {f"{k[0]}:{k[1]}": v for k, v in cache.items() if v[0] > current}
    with open(CACHE_FILE, 'w') as f:
        json.dump(clean_cache, f)


def build_multiply_response(tx_id: int, domain: str) -> bytes | None:
    if ".multiply." not in domain:
        return None
    try:
        left_part = domain.split(".multiply.")[0]
        result = 1
        for num in left_part.split("."):
            if num.isdigit():
                result = (result * int(num)) % 256

        header = struct.pack('!HHHHHH', tx_id, 0x8180, 1, 1, 0, 0)
        question = pack_domain_name(domain) + struct.pack('!HH', 1, 1)
        answer = struct.pack('!HHHIH', 0xC00C, 1, 1, 300, 4) + socket.inet_aton(f"127.0.0.{result}")
        return header + question + answer
    except Exception:
        return None


def extract_next_ns_ip(data: bytes, offset: int, header: DNSHeader) -> str | None:
    for _ in range(header.ancount + header.nscount):
        _, offset = DNSRecord.from_bytes(data, offset)
    for _ in range(header.arcount):
        rec, offset = DNSRecord.from_bytes(data, offset)
        if rec.rtype == 1 and rec.rclass == 1 and rec.rdlength == 4:
            return socket.inet_ntoa(rec.rdata)
    return None


def resolve_iterative(query_data: bytes, domain: str, qtype: int) -> bytes:
    target_ip = ROOT_SERVER

    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3.0)
                sock.sendto(query_data, (target_ip, 53))
                resp_data, _ = sock.recvfrom(4096)

            header = DNSHeader.from_bytes(resp_data)
            _, offset = DNSQuestion.from_bytes(resp_data, 12)

            if header.ancount > 0 or header.rcode != 0:
                return resp_data

            next_ip = extract_next_ns_ip(resp_data, offset, header)
            if next_ip:
                target_ip = next_ip
            else:
                orig_header = DNSHeader.from_bytes(query_data)
                return struct.pack('!HHHHHH', orig_header.tx_id, 0x8182, 1, 0, 0, 0) + query_data[12:]

        except socket.timeout:
            orig_header = DNSHeader.from_bytes(query_data)
            return struct.pack('!HHHHHH', orig_header.tx_id, 0x8182, 1, 0, 0, 0) + query_data[12:]


def process_query(data: bytes) -> bytes:
    try:
        header = DNSHeader.from_bytes(data)
        question, _ = DNSQuestion.from_bytes(data, 12)

        mult_resp = build_multiply_response(header.tx_id, question.name)
        if mult_resp:
            return mult_resp

        cache_key = (question.name, question.qtype)

        if cache_key in cache:
            expiry, hex_data = cache[cache_key]
            if time.time() < expiry:
                cached_bytes = bytes.fromhex(hex_data)
                return struct.pack('!H', header.tx_id) + cached_bytes[2:]
            else:
                del cache[cache_key]

        resolved_data = resolve_iterative(data, question.name, question.qtype)

        cache[cache_key] = (time.time() + 300, resolved_data.hex())
        return struct.pack('!H', header.tx_id) + resolved_data[2:]

    except Exception as e:
        print(f"[ERROR] Не удалось обработать пакет: {e}")
        # Возвращаем SERVFAIL
        return data[:2] + b"\x81\x82" + data[4:]


def udp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    print(f"[UDP] Сервер запущен на {LISTEN_IP}:{LISTEN_PORT}")
    while True:
        data, addr = sock.recvfrom(1024)
        threading.Thread(target=lambda: sock.sendto(process_query(data), addr), daemon=True).start()


def tcp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    sock.listen(5)
    print(f"[TCP] Сервер запущен на {LISTEN_IP}:{LISTEN_PORT}")

    def handle_client(conn):
        with conn:
            try:
                length_bytes = conn.recv(2)
                if not length_bytes: return
                msg_len = struct.unpack('!H', length_bytes)[0]
                data = conn.recv(msg_len)

                response = process_query(data)
                conn.sendall(struct.pack('!H', len(response)) + response)
            except Exception as e:
                print(f"[TCP ERROR] {e}")

    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()


if __name__ == '__main__':
    load_cache()

    def cache_saver():
        while True:
            time.sleep(10)
            save_cache()

    threading.Thread(target=cache_saver, daemon=True).start()
    threading.Thread(target=tcp_server, daemon=True).start()
    udp_server()