import argparse
import hashlib
import json
import os
import re
import random
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit

import pyaes


BASE_DIR = Path(__file__).resolve().parent
INPUT_FILE = BASE_DIR / "listOfProxy.json"
OUTPUT_FILE = BASE_DIR / "ProxyWorks.txt"
MAX_RESULTS = 20
DEFAULT_TIMEOUT = 5.0
MAX_PACKET_SIZE = 1024 * 1024
RES_PQ_CONSTRUCTOR = 0x05162463
PROXY_LINK_PATTERN = re.compile(
    r"(?:tg://proxy\?|https?://(?:t\.me|telegram\.me)/proxy\?)[^\s\"'<>]+",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Proxy:
    host: str
    port: int
    secret: str


class AesCtr:
    def __init__(self, key: bytes, iv: bytes) -> None:
        cipher = pyaes.AESModeOfOperationCTR(key)
        cipher._counter._counter = list(iv)
        self._cipher = cipher

    def process(self, data: bytes) -> bytes:
        return self._cipher.encrypt(data)


def parse_secret(secret: str) -> tuple[bytes, bool]:
    secret = unquote(secret.strip())
    randomized = secret.lower().startswith("dd") and len(secret) == 34
    if secret.lower().startswith("ee") and len(secret) != 32:
        raise ValueError("TLS-секреты с префиксом ee не поддерживаются")
    key_text = secret[2:] if randomized else secret
    if len(key_text) != 32:
        raise ValueError("секрет должен содержать 32 hex-символа (или dd + 32)")
    try:
        return bytes.fromhex(key_text), randomized
    except ValueError as exc:
        raise ValueError("секрет должен быть записан в hex") from exc


def parse_proxy(line: str) -> Proxy:
    line = line.strip()
    if not line or line.startswith("#"):
        raise ValueError("пустая строка или комментарий")

    if line.lower().startswith(("tg://proxy?", "https://t.me/proxy?", "http://t.me/proxy?",
                                "https://telegram.me/proxy?", "http://telegram.me/proxy?")):
        query = parse_qs(urlsplit(line).query)
        host = query.get("server", [""])[0]
        port_text = query.get("port", [""])[0]
        secret = query.get("secret", [""])[0]
    else:
        fields = line.split()
        if len(fields) == 3:
            host, port_text, secret = fields
        elif line.startswith("[") and "]:" in line:
            host, remainder = line[1:].split("]:", 1)
            port_text, secret = remainder.split(":", 1)
        else:
            parts = line.split(":", 2)
            if len(parts) != 3:
                raise ValueError("ожидается host:port:secret или tg://proxy?...")
            host, port_text, secret = parts

    host = host.strip().strip("[]")
    if not host or any(char.isspace() for char in host):
        raise ValueError("не указано корректное имя сервера")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError("порт должен быть числом") from exc
    if not 1 <= port <= 65535:
        raise ValueError("порт должен быть в диапазоне 1–65535")
    parse_secret(secret)
    return Proxy(host, port, secret.strip())


def parse_proxy_record(record: object) -> Proxy:
    if not isinstance(record, dict):
        raise ValueError("ожидается JSON-объект с hostname, port и secret")

    host = record.get("hostname", record.get("host", record.get("server")))
    port = record.get("port")
    secret = record.get("secret")
    proxy_type = record.get("type", "MTPROTO")

    if not isinstance(host, str) or not isinstance(secret, str):
        raise ValueError("hostname и secret должны быть строками")
    if not isinstance(port, (int, str)) or isinstance(port, bool):
        raise ValueError("port должен быть числом")
    if not isinstance(proxy_type, str) or proxy_type.upper() != "MTPROTO":
        raise ValueError("поддерживается только тип MTPROTO")
    formatted_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return parse_proxy(f"{formatted_host}:{port}:{secret}")


def _new_header(secret: bytes, randomized: bool) -> tuple[bytes, AesCtr, AesCtr]:
    excluded_prefixes = (b"PVrG", b"GET ", b"POST", b"\xee" * 4)
    while True:
        header = bytearray(os.urandom(64))
        if (
            header[0] != 0xEF
            and bytes(header[:4]) not in excluded_prefixes
            and header[4:8] != b"\0" * 4
        ):
            break

    reversed_header = bytes(header[55:7:-1])
    encryptor = AesCtr(
        hashlib.sha256(bytes(header[8:40]) + secret).digest(),
        bytes(header[40:56]),
    )
    decryptor = AesCtr(
        hashlib.sha256(reversed_header[:32] + secret).digest(),
        reversed_header[32:48],
    )

    header[56:60] = b"\xdd" * 4 if randomized else b"\xee" * 4
    header[60:62] = struct.pack("<h", 2)
    encrypted_header = encryptor.process(bytes(header))
    header[56:64] = encrypted_header[56:64]
    return bytes(header), encryptor, decryptor


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("прокси закрыл соединение до ответа Telegram")
        chunks.extend(chunk)
    return bytes(chunks)


def _make_req_pq(nonce: bytes) -> bytes:
    msg_id = int(time.time() * (1 << 32)) & ~3
    body = struct.pack("<I", 0x60469778) + nonce
    return struct.pack("<QqI", 0, msg_id, len(body)) + body


def _validate_res_pq(packet: bytes, nonce: bytes) -> None:
    if len(packet) < 40:
        raise ConnectionError("ответ Telegram слишком короткий")
    auth_key_id, _msg_id, message_length = struct.unpack_from("<QqI", packet)
    if auth_key_id != 0 or message_length < 20 or message_length > len(packet) - 20:
        raise ConnectionError("получен некорректный ответ MTProto")
    constructor = struct.unpack_from("<I", packet, 20)[0]
    if constructor != RES_PQ_CONSTRUCTOR or packet[24:40] != nonce:
        raise ConnectionError("прокси не вернул ожидаемый ответ Telegram")


def check_proxy(proxy: Proxy, timeout: float = DEFAULT_TIMEOUT) -> float:
    secret, randomized = parse_secret(proxy.secret)
    header, encryptor, decryptor = _new_header(secret, randomized)
    nonce = os.urandom(16)
    request = _make_req_pq(nonce)
    padding = os.urandom(random.randrange(16)) if randomized else b""
    payload = request + padding

    started = time.perf_counter()
    with socket.create_connection((proxy.host, proxy.port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(header)
        sock.sendall(encryptor.process(struct.pack("<I", len(payload)) + payload))

        encrypted_length = _recv_exact(sock, 4)
        packet_length = struct.unpack("<I", decryptor.process(encrypted_length))[0]
        if not 40 <= packet_length <= MAX_PACKET_SIZE:
            raise ConnectionError(f"недопустимый размер ответа: {packet_length}")
        packet = decryptor.process(_recv_exact(sock, packet_length))

    _validate_res_pq(packet, nonce)
    return (time.perf_counter() - started) * 1000


def load_proxies(path: Path) -> tuple[list[Proxy], int]:
    try:
        records = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"ошибка JSON в строке {exc.lineno}, столбце {exc.colno}: {exc.msg}") from exc
    if isinstance(records, dict) and isinstance(records.get("messages"), list):
        links: list[str] = []

        def find_links(value: object) -> None:
            if isinstance(value, str):
                links.extend(PROXY_LINK_PATTERN.findall(value))
            elif isinstance(value, dict):
                for nested_value in value.values():
                    find_links(nested_value)
            elif isinstance(value, list):
                for nested_value in value:
                    find_links(nested_value)

        find_links(records["messages"])
        if not links:
            raise ValueError("в экспорте Telegram не найдены ссылки на MTProto-прокси")
        records = list(dict.fromkeys(links))
    elif isinstance(records, dict):
        for key in ("proxies", "proxy", "list"):
            if isinstance(records.get(key), list):
                records = records[key]
                break

    if not isinstance(records, list):
        raise ValueError(
            "корень JSON должен быть массивом прокси или Telegram-экспортом с messages"
        )

    proxies: list[Proxy] = []
    invalid_count = 0
    invalid_reasons: dict[str, int] = {}
    seen: set[tuple[str, int, str]] = set()
    for index, record in enumerate(records, 1):
        try:
            proxy = parse_proxy(record) if isinstance(record, str) else parse_proxy_record(record)
        except ValueError as exc:
            invalid_count += 1
            reason = str(exc)
            invalid_reasons[reason] = invalid_reasons.get(reason, 0) + 1
        else:
            key = (proxy.host.lower(), proxy.port, proxy.secret.lower())
            if key not in seen:
                proxies.append(proxy)
                seen.add(key)
    for reason, count in invalid_reasons.items():
        print(f"[!] Пропущено записей: {count} — {reason}")
    return proxies, invalid_count


def write_results(path: Path, results: list[tuple[Proxy, float]]) -> None:
    lines = ["# Рабочие MTProto-прокси. Ссылку можно открыть в Telegram."]
    for proxy, ping in results:
        link = (
            "https://t.me/proxy?"
            f"server={quote(proxy.host, safe='')}"
            f"&port={proxy.port}"
            f"&secret={quote(proxy.secret, safe='')}"
        )
        lines.extend(
            (
                f"# {proxy.host} {proxy.port} MTPROTO {proxy.secret} ping={ping:.1f} ms",
                link,
                "",
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def select_fastest(results: list[tuple[Proxy, float]]) -> list[tuple[Proxy, float]]:
    return sorted(results, key=lambda result: result[1])[:MAX_RESULTS]


def main() -> int:
    parser = argparse.ArgumentParser(description="Проверка MTProto-прокси Telegram")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="таймаут на прокси в секундах")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout должен быть больше нуля")

    if not INPUT_FILE.exists():
        INPUT_FILE.write_text("[]\n", encoding="utf-8")
        print(f"Создан файл со списком прокси: {INPUT_FILE}")
        print("Добавьте прокси в JSON-массив и запустите программу снова.")
        return 0

    try:
        proxies, invalid_count = load_proxies(INPUT_FILE)
    except (OSError, ValueError) as exc:
        print(f"Не удалось прочитать {INPUT_FILE.name}: {exc}")
        return 1
    if not proxies:
        write_results(OUTPUT_FILE, [])
        print(f"В {INPUT_FILE.name} нет корректных прокси для проверки.")
        return 0

    print(f"Проверяю прокси: {len(proxies)} (таймаут {args.timeout:g} с)")
    results: list[tuple[Proxy, float]] = []
    with ThreadPoolExecutor(max_workers=min(50, len(proxies))) as executor:
        futures = {executor.submit(check_proxy, proxy, args.timeout): proxy for proxy in proxies}
        for future in as_completed(futures):
            proxy = futures[future]
            try:
                ping = future.result()
            except (OSError, ValueError, ConnectionError, TimeoutError, struct.error) as exc:
                print(f"[-] {proxy.host}:{proxy.port} — не работает: {exc}")
            else:
                print(f"[+] {proxy.host}:{proxy.port} — MTPROTO, {ping:.1f} ms")
                results.append((proxy, ping))

    selected = select_fastest(results)
    write_results(OUTPUT_FILE, selected)
    print(
        f"\nГотово: рабочих {len(results)}, в ProxyWorks.txt записано "
        f"{len(selected)} прокси с наименьшим ping."
    )
    if invalid_count:
        print(f"Ссылок/записей пропущено по неподдерживаемому или неверному формату: {invalid_count}")
    print(f"Файл результата: {OUTPUT_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
