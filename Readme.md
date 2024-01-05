# anti_SSRF_requests_adapter - SSRF protection for Python Requests Library

## Overview

This library wraps the excellent Python HTTP requests library, [Requests](https://requests.readthedocs.io/en/latest/), by adding several [SSRF](https://en.wikipedia.org/wiki/Server-side_request_forgery) related security measures to HTTP requests.

**Disclaimer**: This library is currently in a developmental stage. Due to the lack of sufficient test case coverage, it should be considered insecure and, at best, experimental. Nonetheless, these features aim to provide a more secure and controlled HTTP request environment, suitable for developers who prioritize stringent security measures in their applications.

### Features
- **Blocking Requests to Non-Public Internet IPs**: Prevents access to (some) private and [reserved IP ranges](https://en.wikipedia.org/wiki/Reserved_IP_addresses).
- **Protection Against DNS Rebinding Attacks**: Resolves IP once per session to safeguard against [DNS rebinding](https://en.wikipedia.org/wiki/DNS_rebinding).
- **Disabling HTTP Redirects**: Redirects are not followed by default to maintain control over request destinations. See [redirect-based SSRF](https://portswigger.net/research/top-10-web-hacking-techniques-of-2017#1).
- **Forbidding IPv6 Usage**: Blocks all connections to IPv6 addresses. IPv6 support might be enabled in the future as its implications for SSRF become clearer. PRs are welcome.

### Limitation
- currently on `GET` is implemented

### Rationale
This library is potentially beneficial in cases where untrusted input is passed to an HTTP client, which we believe is always the case when:
- DNS is being used.
- An untrusted HTTP endpoint is queried, due to the possibility of encountering HTTP redirects (301, 302, 303, 307, 308).

We acknowledge that a more effective approach to securing HTTP client libraries might involve isolation at the OS or network level. However, this library provides an application-level solution as an interim measure.


## Install
```
TBD
pip install git+http://foo/bar
```

## Setup
```
import requests
from anti_ssrf_requests import AnitSSRFRequestAdapter

session = requests.Session()
session.mount('http://', AntiSSRFRequestAdapter())
session.mount('https://', AntiSSRFRequestAdapter())
```

## Usage
```
try:
    response = session.get('http://example.com')
    print(response.content)
except ValueError as e:
    print(f"Error during request: {e}")

```
