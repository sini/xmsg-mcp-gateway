import http.client
import ipaddress
import socket
import ssl
import threading
from datetime import UTC, datetime
from urllib.parse import urlsplit

from standardwebhooks import Webhook


class DestinationError(ValueError):
    pass


TRANSITION = tuple(
    ipaddress.ip_network(n)
    for n in (
        "::/96",
        "::ffff:0:0/96",
        "fec0::/10",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "2002::/16",
        "2001::/32",
    )
)
DNS_TIMEOUT = 3
REQUEST_TIMEOUT = 10
_DNS_SLOTS = threading.BoundedSemaphore(4)


def bounded_dns(host, port):
    if not _DNS_SLOTS.acquire(blocking=False):
        raise DestinationError("resolver_busy")
    finished = threading.Event()
    result = []

    def lookup():
        try:
            result.append(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except OSError:
            result.append(None)
        finally:
            _DNS_SLOTS.release()
            finished.set()

    threading.Thread(target=lookup, daemon=True).start()
    if not finished.wait(DNS_TIMEOUT) or not result[0]:
        raise DestinationError("dns_failed_or_timeout")
    return result[0]


def public_address(address):
    ip = ipaddress.ip_address(address)
    return (
        ip.is_global
        and not ip.is_multicast
        and not any(ip.version == net.version and ip in net for net in TRANSITION)
        and not (isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped)
    )


def resolve_public(url):
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or "%" in parsed.hostname
            or len(url) > 4096
            or any(ord(c) < 33 for c in url)
        ):
            raise DestinationError("invalid_destination")
        port = parsed.port or 443
        answers = bounded_dns(parsed.hostname, port)
        addresses = list(dict.fromkeys(answer[4][0] for answer in answers))
        if not addresses or not all(public_address(address) for address in addresses):
            raise DestinationError("non_public_destination")
        return parsed, addresses
    except (ValueError, OSError) as exc:
        raise DestinationError("invalid_destination") from exc


def dial_ip(address, timeout):
    ip, port = address
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        return sock
    except BaseException:
        sock.close()
        raise


class HTTPS:
    def post(self, url, body, headers):
        parsed, addresses = resolve_public(url)
        connection = http.client.HTTPSConnection(
            parsed.hostname,
            port=parsed.port or 443,
            timeout=10,
            context=ssl.create_default_context(),
        )
        # HTTPSConnection wraps this pinned socket using its original host for SNI/TLS.
        connection._create_connection = lambda address, timeout, *args: dial_ip(
            (addresses[0], parsed.port or 443), timeout
        )
        expired = threading.Event()
        active_socket = [None]

        def abort():
            expired.set()
            sock = active_socket[0] or getattr(connection, "sock", None)
            if sock:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        timer = threading.Timer(REQUEST_TIMEOUT, abort)
        timer.daemon = True
        timer.start()
        try:
            connection.request(
                "POST",
                parsed.path or "/"
                if not parsed.query
                else (parsed.path or "/") + "?" + parsed.query,
                body=body,
                headers=headers,
            )
            active_socket[0] = getattr(connection, "sock", None)
            response = connection.getresponse()
            data = response.read(65537)
            if expired.is_set():
                raise TimeoutError("request_deadline")
            if len(data) > 65536:
                raise DestinationError("response_too_large")
            return response.status, data
        except http.client.HTTPException as exc:
            raise OSError("https_protocol_error") from exc
        finally:
            timer.cancel()
            connection.close()


def signed_post(http, url, body, event_id, subscription_id, keys):
    stamp = datetime.now(UTC)
    signature = " ".join(
        Webhook(key).sign(event_id, stamp, body.decode()) for key in keys
    )
    headers = {
        "Content-Type": "application/json",
        "webhook-id": event_id,
        "webhook-timestamp": str(int(stamp.timestamp())),
        "webhook-signature": signature,
        "X-MCP-Subscription-Id": subscription_id,
    }
    return http.post(url, body, headers)
