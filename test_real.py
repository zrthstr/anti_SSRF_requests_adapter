import requests
from anti_SSRF_requests_adapter import AntiSSRFSession

assrf_session = AntiSSRFSession()

"""
additionaly to the unit tests some real test seem nececary
Test security controlls:
* IPv6 blocking
* a few NAT request
* some HTTP redirects
* fetch some Rebinding URL

* Test the propper functioning of allowed requests:
    briefly test all HTTP verbs, after adding :D

"""


def main():

    try:
        response = assrf_session.get('http://example.com')
        print(response.content)
    except ValueError as e:
        print(f"An error occurred: {e}")

    response = assrf_session.get("http://[2a00:1450:4026:803::200e]/")


if __name__ == "__main__":
    main()


