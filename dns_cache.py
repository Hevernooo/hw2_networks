import socket
import struct
import threading
from dataclasses import dataclass

ROOT_SERVER = '198.41.0.4'
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


@dataclass
class DNSHeader:
    tx_id: int
    flags: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int

    @property
    def rcode(self) -> int:
        return self.flags & 0x000F

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
        _, offset = parse_domain_name(data, offset)
        rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        return cls(rtype, rclass, ttl, rdlength, rdata), offset + rdlength


def build_multiply_response(query_data: bytes, domain: str) -> bytes | None:
    if ".multiply" not in domain:
        return None

    try:
        header = DNSHeader.from_bytes(query_data)
        _, offset = DNSQuestion.from_bytes(query_data, 12)

        original_question = query_data[12:offset]

        left_part = domain.split(".multiply")[0]
        result = 1
        for num in left_part.split("."):
            if num.isdigit():
                result = (result * int(num)) % 256

        resp_header = struct.pack('!HHHHHH', header.tx_id, 0x8180, 1, 1, 0, 0)
        answer = struct.pack('!HHHIH', 0xC00C, 1, 1, 300, 4) + socket.inet_aton(f"127.0.0.{result}")

        return resp_header + original_question + answer
    except Exception as e:
        print(f"[MULTIPLY ERROR] Ошибка при сборке пакета: {e}")
        return None


def extract_next_ns_ip(data: bytes, offset: int, header: DNSHeader) -> str | None:
    for _ in range(header.ancount + header.nscount):
        _, offset = DNSRecord.from_bytes(data, offset)
    for _ in range(header.arcount):
        rec, offset = DNSRecord.from_bytes(data, offset)
        if rec.rtype == 1 and rec.rclass == 1 and rec.rdlength == 4:
            return socket.inet_ntoa(rec.rdata)
    return None


def resolve_iterative(query_data: bytes) -> bytes:
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

        mult_resp = build_multiply_response(data, question.name)
        if mult_resp:
            return mult_resp

        resolved_data = resolve_iterative(data)
        orig_flags = struct.unpack('!H', resolved_data[2:4])[0]
        new_flags = orig_flags | 0x0080

        return struct.pack('!HH', header.tx_id, new_flags) + resolved_data[4:]
    except Exception as e:
        print(f"[ERROR] Не удалось обработать пакет: {e}")
        return data[:2] + b"\x81\x82" + data[4:]


def udp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    print(f"[UDP] Сервер запущен на {LISTEN_IP}:{LISTEN_PORT}")
    while True:
        data, addr = sock.recvfrom(1024)
        threading.Thread(target=lambda d=data, a=addr: sock.sendto(process_query(d), a), daemon=True).start()


if __name__ == '__main__':
    udp_server()
