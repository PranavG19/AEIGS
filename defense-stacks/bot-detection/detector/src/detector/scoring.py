import os

BROWSER_USER_AGENTS = [
    "Mozilla/5.0",
    "Chrome/",
    "Firefox/",
    "Safari/",
    "Edge/",
]

REQUIRED_BROWSER_HEADERS = [
    "accept",
    "accept-language",
    "accept-encoding",
]


def score_headers(headers: dict[str, str]) -> float:
    ua = headers.get("user-agent", "")
    if not ua:
        return 0.0
    if not any(sig in ua for sig in BROWSER_USER_AGENTS):
        return 0.1
    present = sum(1 for h in REQUIRED_BROWSER_HEADERS if h in headers)
    ua_score = 0.4
    header_score = 0.6 * (present / len(REQUIRED_BROWSER_HEADERS))
    return ua_score + header_score


def score_request(headers: dict[str, str]) -> float:
    return score_headers(headers)


def is_bot(headers: dict[str, str]) -> bool:
    threshold = float(os.environ.get("BOT_THRESHOLD", "0.5"))
    return score_request(headers) < threshold
