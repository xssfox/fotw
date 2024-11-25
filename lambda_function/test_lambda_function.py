import unittest

from unittest import mock
from unittest.mock import Mock
import os
import pyotp
import datetime
import hashlib
import base64
from freezegun import freeze_time
import gzip
import json

mock.patch.dict(os.environ, {"SECRET": "1234567890"}, clear=True).start()
import lambda_function
lambda_function.VERIFICATION_SIGDATA = "AA9FOTWFT8"

class TestValidate(unittest.TestCase):
    def test_valid(self):
        
        timestamp = "2024-09-05T19:07:00Z"
        callsign = "VK3FUR"
        user_secret = hashlib.sha3_512(("1234567890" + callsign).encode()).digest()[:10]
        user_secret_b32 = base64.b32encode(user_secret)

        ts = int(datetime.datetime.fromisoformat(timestamp).timestamp()//30)
        code = pyotp.HOTP(user_secret_b32).at(ts)

        output = lambda_function.validate(
            {
                "pathParameters": {
                    "callsign": callsign,
                    "timestamp": timestamp,
                    "code": f"{code}.text",
                }
            },{}
        )
        self.assertTrue(output['body'].endswith(" VERIFIED"))

    def test_invalid(self):
        
        timestamp = "2024-09-05T19:07:00Z"
        callsign = "VK3FUR"

        code = "000000"

        output = lambda_function.validate(
            {
                "pathParameters": {
                    "callsign": callsign,
                    "timestamp": timestamp,
                    "code": f"{code}.text",
                }
            },{}
        )
        self.assertFalse(output['body'].endswith(" VERIFIED"))

    @mock.patch('urllib.request.urlopen')
    def test_call_9dx_verified(self, urlopen):
        timestamp = "2024-09-05T19:07:00Z"
        callsign = "VK3FUR"

        code = "000000"

        return_read = Mock()
        return_read.read.side_effect = ["blah VERIFIED"]
        urlopen.return_value = return_read

        output = lambda_function.validate(
            {
                "pathParameters": {
                    "callsign": callsign,
                    "timestamp": timestamp,
                    "code": f"{code}.text",
                }
            },{}
        )
        self.assertTrue(output['body'].endswith(" VERIFIED"))

    @freeze_time("2020-04-26T19:07:00Z")
    def test_time_in_future(self):
        
        timestamp = "2020-04-26T19:07:30Z"
        callsign = "VK3FUR"
        user_secret = hashlib.sha3_512(("1234567890" + callsign).encode()).digest()[:10]
        user_secret_b32 = base64.b32encode(user_secret)

        ts = int(datetime.datetime.fromisoformat(timestamp).timestamp()//30)
        code = pyotp.HOTP(user_secret_b32).at(ts)

        with self.assertRaises(ValueError):
            output = lambda_function.validate(
                {
                    "pathParameters": {
                        "callsign": callsign,
                        "timestamp": timestamp,
                        "code": f"{code}.text",
                    }
                },{}
            )

    @freeze_time("2020-04-26T19:07:31Z")
    def test_time_just_in_the_past(self):
        
        timestamp = "2020-04-26T19:07:31Z"
        callsign = "VK3FUR"
        user_secret = hashlib.sha3_512(("1234567890" + callsign).encode()).digest()[:10]
        user_secret_b32 = base64.b32encode(user_secret)

        ts = int(datetime.datetime.fromisoformat(timestamp).timestamp()//30)
        code = pyotp.HOTP(user_secret_b32).at(ts)

        output = lambda_function.validate(
            {
                "pathParameters": {
                    "callsign": callsign,
                    "timestamp": timestamp,
                    "code": f"{code}.text",
                }
            },{}
        )
        self.assertTrue(output['body'].endswith(" VERIFIED"))

# Note that AA9FOTW is used instead of ZZ9FOTW for testing as we don't want to commit a signed log to the repo
EXAMPLE_TQ8 = """
<TQSL_IDENT:54>TQSL V2.7.5 Lib: V2.5 Config: V11.29 AllowDupes: false

<Rec_Type:5>tCERT
<CERT_UID:1>1
<CERTIFICATE:1890>MIIFbTCCBFWgAwIBAgIDCuszMA0GCSqGSIb3DQEBCwUAMIHYMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQ1QxEjAQBgNVBAcMCU5ld2luZ3RvbjEkMCIGA1UECgwbQW1l
cmljYW4gUmFkaW8gUmVsYXkgTGVhZ3VlMR0wGwYDVQQLDBRMb2dib29rIG9mIHRo
ZSBXb3JsZDErMCkGA1UEAwwiTG9nYm9vayBvZiB0aGUgV29ybGQgUHJvZHVjdGlv
biBDQTEYMBYGCgmSJomT8ixkARkWCGFycmwub3JnMRwwGgYJKoZIhvcNAQkBFg1s
b3R3QGFycmwub3JnMB4XDTIzMDMyNzEwMzU0NVoXDTI2MDMyNjEwMzU0NVowVzEV
MBMGCSsGAQQB4DwBAQwGVkszRlVSMRkwFwYDVQQDDBBNaWNoYWVsYSBXaGVlbGVy
MSMwIQYJKoZIhvcNAQkBFhR2azNmdXJAbWljaGFlbGEubGdidDCBnzANBgkqhkiG
9w0BAQEFAAOBjQAwgYkCgYEAnpAJuTZVRRytzXF3l86kiLMOehe4KB1uUTvwGVYa
sz6ZWbvs6FEk5J7Gui8Zlod8F9iTEW3XoyCNjEAdzFvjnse9PPRHhJPIEQTaunG/
j+CfB8ha3B+S1uu9NuALzC58+JI0QF+YWhGcCNzr4QEoTd6QgrOerJGYRLptfuoF
kRMCAwEAAaOCAkIwggI+MB0GA1UdDgQWBBSAjH68tNPwTP3Oa4MSBAzYdkz5lTCC
ARQGA1UdIwSCAQswggEHgBSon29qgLN1wj/t5xz8TzNwqOwuv6GB2KSB1TCB0jEL
MAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNUMRIwEAYDVQQHDAlOZXdpbmd0b24xJDAi
BgNVBAoMG0FtZXJpY2FuIFJhZGlvIFJlbGF5IExlYWd1ZTEdMBsGA1UECwwUTG9n
Ym9vayBvZiB0aGUgV29ybGQxJTAjBgNVBAMMHExvZ2Jvb2sgb2YgdGhlIFdvcmxk
IFJvb3QgQ0ExGDAWBgoJkiaJk/IsZAEZFghhcnJsLm9yZzEcMBoGCSqGSIb3DQEJ
ARYNbG90d0BhcnJsLm9yZ4IUV31ApzN0aZACaQt7FGB26Mu5t4kwCQYDVR0TBAIw
ADALBgNVHQ8EBAMCBeAwFwYJKwYBBAHgPAECBAoyMDE4LTA0LTAxMBcGCSsGAQQB
4DwBAwQKMjAyNi0wMy0yNjAQBgkrBgEEAeA8AQQEAzE1MDCBqAYJKwYBBAHgPAEF
BIGaL0M9VVMvU1Q9Q1QvTD1OZXdpbmd0b24vTz1BbWVyaWNhbiBSYWRpbyBSZWxh
eSBMZWFndWUvT1U9TG9nYm9vayBvZiB0aGUgV29ybGQvQ049TG9nYm9vayBvZiB0
aGUgV29ybGQgUHJvZHVjdGlvbiBDQS9EQz1hcnJsLm9yZy9FbWFpbD1sb3R3QGFy
cmwub3JnOzUxNzQyMTANBgkqhkiG9w0BAQsFAAOCAQEAe9iRCzJorB8YIceztG11
4dvyAjpl2kY6ds4EzwqMF6DQE2iyl3vQbHy2Taf4aW2TaSzOH0wXG3V2dd2v0+Q7
ag7w89D37MMJpjC6Qp1Zu0TKnxzA/PdaQup1JCPIyev0pmWG0q+lFx9os9yXIdGw
i93JJJi7w16iAtGwI+Kt5LKaQxlFsPj1pG0HbhRI5cxThymrJUYUl9kzksWWzkSQ
LTJCL0SobV37WAmSw0ArcgI5Kgz2W/MMvGHDRMWEbvWxGTTZj6wHzaQ4UKhRl3mp
kwI0u5CXnH8uhiN1mbrkTdfEJEkGEqQ+iqfVn2iouhLi5DLaF8raFBhQBoD3ejYT
Cg==
<eor>

<Rec_Type:8>tSTATION
<STATION_UID:1>1
<CERT_UID:1>1
<CALL:6>VK3FUR
<DXCC:3>150
<GRIDSQUARE:4>QF22
<ITUZ:2>59
<CQZ:2>30
<AU_STATE:3>VIC
<eor>

<Rec_Type:8>tCONTACT
<STATION_UID:1>1
<CALL:7>AA9FOTW
<BAND:3>40M
<MODE:3>FT8
<QSO_DATE:10>2024-10-25
<QSO_TIME:9>12:34:00Z
<SIGN_LOTW_V2.0:175:6>BEQEef3tN5+gRs2J+ynH3Eu4wOxZW/UG3zVkY1ZkK5av1cVzzUkmskgYeSvr+e0Z
NWC2yYzoLW5wjE65BvyxzQQG0AISdgpzoO8r66U8fzvkrJZRsYN8RIs42hVTygsi
jPJ+4W8/MTs+gYsVlRY3AJzhnAkXcp0Ld9HroytslBc=
<SIGNDATA:43>VIC30QF225940MAA9FOTWFT82024-10-2512:34:00Z
<eor>
"""

EXAMPLE_TQ8_SIGN_DATA_WRONG = """
<TQSL_IDENT:54>TQSL V2.7.5 Lib: V2.5 Config: V11.29 AllowDupes: false

<Rec_Type:5>tCERT
<CERT_UID:1>1
<CERTIFICATE:1890>MIIFbTCCBFWgAwIBAgIDCuszMA0GCSqGSIb3DQEBCwUAMIHYMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQ1QxEjAQBgNVBAcMCU5ld2luZ3RvbjEkMCIGA1UECgwbQW1l
cmljYW4gUmFkaW8gUmVsYXkgTGVhZ3VlMR0wGwYDVQQLDBRMb2dib29rIG9mIHRo
ZSBXb3JsZDErMCkGA1UEAwwiTG9nYm9vayBvZiB0aGUgV29ybGQgUHJvZHVjdGlv
biBDQTEYMBYGCgmSJomT8ixkARkWCGFycmwub3JnMRwwGgYJKoZIhvcNAQkBFg1s
b3R3QGFycmwub3JnMB4XDTIzMDMyNzEwMzU0NVoXDTI2MDMyNjEwMzU0NVowVzEV
MBMGCSsGAQQB4DwBAQwGVkszRlVSMRkwFwYDVQQDDBBNaWNoYWVsYSBXaGVlbGVy
MSMwIQYJKoZIhvcNAQkBFhR2azNmdXJAbWljaGFlbGEubGdidDCBnzANBgkqhkiG
9w0BAQEFAAOBjQAwgYkCgYEAnpAJuTZVRRytzXF3l86kiLMOehe4KB1uUTvwGVYa
sz6ZWbvs6FEk5J7Gui8Zlod8F9iTEW3XoyCNjEAdzFvjnse9PPRHhJPIEQTaunG/
j+CfB8ha3B+S1uu9NuALzC58+JI0QF+YWhGcCNzr4QEoTd6QgrOerJGYRLptfuoF
kRMCAwEAAaOCAkIwggI+MB0GA1UdDgQWBBSAjH68tNPwTP3Oa4MSBAzYdkz5lTCC
ARQGA1UdIwSCAQswggEHgBSon29qgLN1wj/t5xz8TzNwqOwuv6GB2KSB1TCB0jEL
MAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNUMRIwEAYDVQQHDAlOZXdpbmd0b24xJDAi
BgNVBAoMG0FtZXJpY2FuIFJhZGlvIFJlbGF5IExlYWd1ZTEdMBsGA1UECwwUTG9n
Ym9vayBvZiB0aGUgV29ybGQxJTAjBgNVBAMMHExvZ2Jvb2sgb2YgdGhlIFdvcmxk
IFJvb3QgQ0ExGDAWBgoJkiaJk/IsZAEZFghhcnJsLm9yZzEcMBoGCSqGSIb3DQEJ
ARYNbG90d0BhcnJsLm9yZ4IUV31ApzN0aZACaQt7FGB26Mu5t4kwCQYDVR0TBAIw
ADALBgNVHQ8EBAMCBeAwFwYJKwYBBAHgPAECBAoyMDE4LTA0LTAxMBcGCSsGAQQB
4DwBAwQKMjAyNi0wMy0yNjAQBgkrBgEEAeA8AQQEAzE1MDCBqAYJKwYBBAHgPAEF
BIGaL0M9VVMvU1Q9Q1QvTD1OZXdpbmd0b24vTz1BbWVyaWNhbiBSYWRpbyBSZWxh
eSBMZWFndWUvT1U9TG9nYm9vayBvZiB0aGUgV29ybGQvQ049TG9nYm9vayBvZiB0
aGUgV29ybGQgUHJvZHVjdGlvbiBDQS9EQz1hcnJsLm9yZy9FbWFpbD1sb3R3QGFy
cmwub3JnOzUxNzQyMTANBgkqhkiG9w0BAQsFAAOCAQEAe9iRCzJorB8YIceztG11
4dvyAjpl2kY6ds4EzwqMF6DQE2iyl3vQbHy2Taf4aW2TaSzOH0wXG3V2dd2v0+Q7
ag7w89D37MMJpjC6Qp1Zu0TKnxzA/PdaQup1JCPIyev0pmWG0q+lFx9os9yXIdGw
i93JJJi7w16iAtGwI+Kt5LKaQxlFsPj1pG0HbhRI5cxThymrJUYUl9kzksWWzkSQ
LTJCL0SobV37WAmSw0ArcgI5Kgz2W/MMvGHDRMWEbvWxGTTZj6wHzaQ4UKhRl3mp
kwI0u5CXnH8uhiN1mbrkTdfEJEkGEqQ+iqfVn2iouhLi5DLaF8raFBhQBoD3ejYT
Cg==
<eor>

<Rec_Type:8>tSTATION
<STATION_UID:1>1
<CERT_UID:1>1
<CALL:6>VK3FUR
<DXCC:3>150
<GRIDSQUARE:4>QF22
<ITUZ:2>59
<CQZ:2>30
<AU_STATE:3>VIC
<eor>

<Rec_Type:8>tCONTACT
<STATION_UID:1>1
<CALL:7>AA9FOTW
<BAND:3>40M
<MODE:3>FT8
<QSO_DATE:10>2024-10-25
<QSO_TIME:9>12:34:00Z
<SIGN_LOTW_V2.0:175:6>BEQEef3tN5+gRs2J+ynH3Eu4wOxZW/UG3zVkY1ZkK5av1cVzzUkmskgYeSvr+e0Z
NWC2yYzoLW5wjE65BvyxzQQG0AISdgpzoO8r66U8fzvkrJZRsYN8RIs42hVTygsi
jPJ+4W8/MTs+gYsVlRY3AJzhnAkXcp0Ld9HroytslBc=
<SIGNDATA:43>ZVIC30QF225940MAA9FOTWFT82024-10-2512:34:00Z
<eor>
"""

EXAMPLE_TQ8_MORE_RECORDS = """
<TQSL_IDENT:54>TQSL V2.7.5 Lib: V2.5 Config: V11.29 AllowDupes: false

<Rec_Type:5>tCERT
<CERT_UID:1>1
<CERTIFICATE:1890>MIIFbTCCBFWgAwIBAgIDCuszMA0GCSqGSIb3DQEBCwUAMIHYMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQ1QxEjAQBgNVBAcMCU5ld2luZ3RvbjEkMCIGA1UECgwbQW1l
cmljYW4gUmFkaW8gUmVsYXkgTGVhZ3VlMR0wGwYDVQQLDBRMb2dib29rIG9mIHRo
ZSBXb3JsZDErMCkGA1UEAwwiTG9nYm9vayBvZiB0aGUgV29ybGQgUHJvZHVjdGlv
biBDQTEYMBYGCgmSJomT8ixkARkWCGFycmwub3JnMRwwGgYJKoZIhvcNAQkBFg1s
b3R3QGFycmwub3JnMB4XDTIzMDMyNzEwMzU0NVoXDTI2MDMyNjEwMzU0NVowVzEV
MBMGCSsGAQQB4DwBAQwGVkszRlVSMRkwFwYDVQQDDBBNaWNoYWVsYSBXaGVlbGVy
MSMwIQYJKoZIhvcNAQkBFhR2azNmdXJAbWljaGFlbGEubGdidDCBnzANBgkqhkiG
9w0BAQEFAAOBjQAwgYkCgYEAnpAJuTZVRRytzXF3l86kiLMOehe4KB1uUTvwGVYa
sz6ZWbvs6FEk5J7Gui8Zlod8F9iTEW3XoyCNjEAdzFvjnse9PPRHhJPIEQTaunG/
j+CfB8ha3B+S1uu9NuALzC58+JI0QF+YWhGcCNzr4QEoTd6QgrOerJGYRLptfuoF
kRMCAwEAAaOCAkIwggI+MB0GA1UdDgQWBBSAjH68tNPwTP3Oa4MSBAzYdkz5lTCC
ARQGA1UdIwSCAQswggEHgBSon29qgLN1wj/t5xz8TzNwqOwuv6GB2KSB1TCB0jEL
MAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNUMRIwEAYDVQQHDAlOZXdpbmd0b24xJDAi
BgNVBAoMG0FtZXJpY2FuIFJhZGlvIFJlbGF5IExlYWd1ZTEdMBsGA1UECwwUTG9n
Ym9vayBvZiB0aGUgV29ybGQxJTAjBgNVBAMMHExvZ2Jvb2sgb2YgdGhlIFdvcmxk
IFJvb3QgQ0ExGDAWBgoJkiaJk/IsZAEZFghhcnJsLm9yZzEcMBoGCSqGSIb3DQEJ
ARYNbG90d0BhcnJsLm9yZ4IUV31ApzN0aZACaQt7FGB26Mu5t4kwCQYDVR0TBAIw
ADALBgNVHQ8EBAMCBeAwFwYJKwYBBAHgPAECBAoyMDE4LTA0LTAxMBcGCSsGAQQB
4DwBAwQKMjAyNi0wMy0yNjAQBgkrBgEEAeA8AQQEAzE1MDCBqAYJKwYBBAHgPAEF
BIGaL0M9VVMvU1Q9Q1QvTD1OZXdpbmd0b24vTz1BbWVyaWNhbiBSYWRpbyBSZWxh
eSBMZWFndWUvT1U9TG9nYm9vayBvZiB0aGUgV29ybGQvQ049TG9nYm9vayBvZiB0
aGUgV29ybGQgUHJvZHVjdGlvbiBDQS9EQz1hcnJsLm9yZy9FbWFpbD1sb3R3QGFy
cmwub3JnOzUxNzQyMTANBgkqhkiG9w0BAQsFAAOCAQEAe9iRCzJorB8YIceztG11
4dvyAjpl2kY6ds4EzwqMF6DQE2iyl3vQbHy2Taf4aW2TaSzOH0wXG3V2dd2v0+Q7
ag7w89D37MMJpjC6Qp1Zu0TKnxzA/PdaQup1JCPIyev0pmWG0q+lFx9os9yXIdGw
i93JJJi7w16iAtGwI+Kt5LKaQxlFsPj1pG0HbhRI5cxThymrJUYUl9kzksWWzkSQ
LTJCL0SobV37WAmSw0ArcgI5Kgz2W/MMvGHDRMWEbvWxGTTZj6wHzaQ4UKhRl3mp
kwI0u5CXnH8uhiN1mbrkTdfEJEkGEqQ+iqfVn2iouhLi5DLaF8raFBhQBoD3ejYT
Cg==
<eor>

<Rec_Type:8>tSTATION
<STATION_UID:1>1
<CERT_UID:1>1
<CALL:6>VK3FUR
<DXCC:3>150
<GRIDSQUARE:4>QF22
<ITUZ:2>59
<CQZ:2>30
<AU_STATE:3>VIC
<eor>

<Rec_Type:8>tCONTACT
<STATION_UID:1>1
<CALL:7>AA9FOTW
<BAND:3>40M
<MODE:3>FT8
<QSO_DATE:10>2024-10-25
<QSO_TIME:9>12:34:00Z
<SIGN_LOTW_V2.0:175:6>BEQEef3tN5+gRs2J+ynH3Eu4wOxZW/UG3zVkY1ZkK5av1cVzzUkmskgYeSvr+e0Z
NWC2yYzoLW5wjE65BvyxzQQG0AISdgpzoO8r66U8fzvkrJZRsYN8RIs42hVTygsi
jPJ+4W8/MTs+gYsVlRY3AJzhnAkXcp0Ld9HroytslBc=
<SIGNDATA:43>VIC30QF225940MAA9FOTWFT82024-10-2512:34:00Z
<eor>

<Rec_Type:8>tSTATION
<STATION_UID:1>1
<CERT_UID:1>1
<CALL:6>VK3FUR
<DXCC:3>150
<GRIDSQUARE:4>QF22
<ITUZ:2>59
<CQZ:2>30
<AU_STATE:3>VIC
<eor>

<Rec_Type:8>tCONTACT
<STATION_UID:1>1
<CALL:7>AA9FOTW
<BAND:3>40M
<MODE:3>FT8
<QSO_DATE:10>2024-10-25
<QSO_TIME:9>12:34:00Z
<SIGN_LOTW_V2.0:175:6>BEQEef3tN5+gRs2J+ynH3Eu4wOxZW/UG3zVkY1ZkK5av1cVzzUkmskgYeSvr+e0Z
NWC2yYzoLW5wjE65BvyxzQQG0AISdgpzoO8r66U8fzvkrJZRsYN8RIs42hVTygsi
jPJ+4W8/MTs+gYsVlRY3AJzhnAkXcp0Ld9HroytslBc=
<SIGNDATA:43>VIC30QF225940MAA9FOTWFT82024-10-2512:34:00Z
<eor>
"""

EXAMPLE_TQ8_WRONG_CERT = """
<TQSL_IDENT:54>TQSL V2.7.5 Lib: V2.5 Config: V11.29 AllowDupes: false

<Rec_Type:5>tCERT
<CERT_UID:1>1
<CERTIFICATE:2251>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
euRFuHg4j85bSZ3Nd+cvb09Fdr5xeJtHsCIn4g==
<eor>

<Rec_Type:8>tSTATION
<STATION_UID:1>1
<CERT_UID:1>1
<CALL:6>VK3FUR
<DXCC:3>150
<GRIDSQUARE:4>QF22
<ITUZ:2>59
<CQZ:2>30
<AU_STATE:3>VIC
<eor>

<Rec_Type:8>tCONTACT
<STATION_UID:1>1
<CALL:7>AA9FOTW
<BAND:3>40M
<MODE:3>FT8
<QSO_DATE:10>2024-10-25
<QSO_TIME:9>12:34:00Z
<SIGN_LOTW_V2.0:175:6>BEQEef3tN5+gRs2J+ynH3Eu4wOxZW/UG3zVkY1ZkK5av1cVzzUkmskgYeSvr+e0Z
NWC2yYzoLW5wjE65BvyxzQQG0AISdgpzoO8r66U8fzvkrJZRsYN8RIs42hVTygsi
jPJ+4W8/MTs+gYsVlRY3AJzhnAkXcp0Ld9HroytslBc=
<SIGNDATA:43>VIC30QF225940MAA9FOTWFT82024-10-2512:34:00Z
<eor>
"""

EXAMPLE_TQ8_WRONG_CALL_SIGNED = """<TQSL_IDENT:54>TQSL V2.7.5 Lib: V2.5 Config: V11.29 AllowDupes: false

<Rec_Type:5>tCERT
<CERT_UID:1>1
<CERTIFICATE:1890>MIIFbTCCBFWgAwIBAgIDCuszMA0GCSqGSIb3DQEBCwUAMIHYMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQ1QxEjAQBgNVBAcMCU5ld2luZ3RvbjEkMCIGA1UECgwbQW1l
cmljYW4gUmFkaW8gUmVsYXkgTGVhZ3VlMR0wGwYDVQQLDBRMb2dib29rIG9mIHRo
ZSBXb3JsZDErMCkGA1UEAwwiTG9nYm9vayBvZiB0aGUgV29ybGQgUHJvZHVjdGlv
biBDQTEYMBYGCgmSJomT8ixkARkWCGFycmwub3JnMRwwGgYJKoZIhvcNAQkBFg1s
b3R3QGFycmwub3JnMB4XDTIzMDMyNzEwMzU0NVoXDTI2MDMyNjEwMzU0NVowVzEV
MBMGCSsGAQQB4DwBAQwGVkszRlVSMRkwFwYDVQQDDBBNaWNoYWVsYSBXaGVlbGVy
MSMwIQYJKoZIhvcNAQkBFhR2azNmdXJAbWljaGFlbGEubGdidDCBnzANBgkqhkiG
9w0BAQEFAAOBjQAwgYkCgYEAnpAJuTZVRRytzXF3l86kiLMOehe4KB1uUTvwGVYa
sz6ZWbvs6FEk5J7Gui8Zlod8F9iTEW3XoyCNjEAdzFvjnse9PPRHhJPIEQTaunG/
j+CfB8ha3B+S1uu9NuALzC58+JI0QF+YWhGcCNzr4QEoTd6QgrOerJGYRLptfuoF
kRMCAwEAAaOCAkIwggI+MB0GA1UdDgQWBBSAjH68tNPwTP3Oa4MSBAzYdkz5lTCC
ARQGA1UdIwSCAQswggEHgBSon29qgLN1wj/t5xz8TzNwqOwuv6GB2KSB1TCB0jEL
MAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNUMRIwEAYDVQQHDAlOZXdpbmd0b24xJDAi
BgNVBAoMG0FtZXJpY2FuIFJhZGlvIFJlbGF5IExlYWd1ZTEdMBsGA1UECwwUTG9n
Ym9vayBvZiB0aGUgV29ybGQxJTAjBgNVBAMMHExvZ2Jvb2sgb2YgdGhlIFdvcmxk
IFJvb3QgQ0ExGDAWBgoJkiaJk/IsZAEZFghhcnJsLm9yZzEcMBoGCSqGSIb3DQEJ
ARYNbG90d0BhcnJsLm9yZ4IUV31ApzN0aZACaQt7FGB26Mu5t4kwCQYDVR0TBAIw
ADALBgNVHQ8EBAMCBeAwFwYJKwYBBAHgPAECBAoyMDE4LTA0LTAxMBcGCSsGAQQB
4DwBAwQKMjAyNi0wMy0yNjAQBgkrBgEEAeA8AQQEAzE1MDCBqAYJKwYBBAHgPAEF
BIGaL0M9VVMvU1Q9Q1QvTD1OZXdpbmd0b24vTz1BbWVyaWNhbiBSYWRpbyBSZWxh
eSBMZWFndWUvT1U9TG9nYm9vayBvZiB0aGUgV29ybGQvQ049TG9nYm9vayBvZiB0
aGUgV29ybGQgUHJvZHVjdGlvbiBDQS9EQz1hcnJsLm9yZy9FbWFpbD1sb3R3QGFy
cmwub3JnOzUxNzQyMTANBgkqhkiG9w0BAQsFAAOCAQEAe9iRCzJorB8YIceztG11
4dvyAjpl2kY6ds4EzwqMF6DQE2iyl3vQbHy2Taf4aW2TaSzOH0wXG3V2dd2v0+Q7
ag7w89D37MMJpjC6Qp1Zu0TKnxzA/PdaQup1JCPIyev0pmWG0q+lFx9os9yXIdGw
i93JJJi7w16iAtGwI+Kt5LKaQxlFsPj1pG0HbhRI5cxThymrJUYUl9kzksWWzkSQ
LTJCL0SobV37WAmSw0ArcgI5Kgz2W/MMvGHDRMWEbvWxGTTZj6wHzaQ4UKhRl3mp
kwI0u5CXnH8uhiN1mbrkTdfEJEkGEqQ+iqfVn2iouhLi5DLaF8raFBhQBoD3ejYT
Cg==
<eor>

<Rec_Type:8>tSTATION
<STATION_UID:1>1
<CERT_UID:1>1
<CALL:6>VK3FUR
<DXCC:3>150
<GRIDSQUARE:4>QF22
<ITUZ:2>59
<CQZ:2>30
<AU_STATE:3>VIC
<eor>

<Rec_Type:8>tCONTACT
<STATION_UID:1>1
<CALL:7>BB9FOTW
<BAND:3>40M
<MODE:3>FT8
<QSO_DATE:10>2024-10-25
<QSO_TIME:9>12:34:00Z
<SIGN_LOTW_V2.0:175:6>UY5+ztU3AXCp+IKUr5do8093LyCYW7fj1qzSp42ruA8DmgMyg3fGLldF8ClprEhN
BkC0I6ZAq86zezZq9quM7/krbOWIBrSdglXAiFdHyKQjv2/BT/Nc4agW4HLXhSe0
jGPIKMiw/z5MfmxrdxDmzWjbdptLhXx1q3aKRS3IaNM=
<SIGNDATA:43>VIC30QF225940MBB9FOTWFT82024-10-2512:34:00Z
<eor>
"""

@freeze_time("2024-10-25")
class TestVerify(unittest.TestCase):
    def test_sign_data_wrong_log(self):
         with self.assertRaises(ValueError):
            lambda_function.verify(
                {
                    "body": base64.encodebytes(gzip.compress(EXAMPLE_TQ8_WRONG_CALL_SIGNED.encode()))
                },{}
            )

    @freeze_time("2027-10-25")
    def test_sign_data_expired(self):
         with self.assertRaises(ValueError) as context:
            lambda_function.verify(
                {
                    "body": base64.encodebytes(gzip.compress(EXAMPLE_TQ8.encode()))
                },{}
            )
            self.assertEqual(context.exception, "Cert time not valid")
    def test_sign_data_invalid(self):
         with self.assertRaises(ValueError):
            lambda_function.verify(
                {
                    "body": base64.encodebytes(gzip.compress(EXAMPLE_TQ8_SIGN_DATA_WRONG.encode()))
                },{}
            )
    def test_more_than_one_record(self):
         with self.assertRaises(ValueError):
            lambda_function.verify(
                {
                    "body": base64.encodebytes(gzip.compress(EXAMPLE_TQ8_MORE_RECORDS.encode()))
                },{}
            )
    def test_cert_not_issued_by_ca(self):
         with self.assertRaises(ValueError):
            lambda_function.verify(
                {
                    "body": base64.encodebytes(gzip.compress(EXAMPLE_TQ8_WRONG_CERT.encode()))
                },{}
            )
    def test_working(self):
        output = lambda_function.verify(
            {
                "body": base64.encodebytes(gzip.compress(EXAMPLE_TQ8.encode()))
            },{}
        )
        self.assertEqual(json.loads(output['body'])['callsign'],"VK3FUR")
    @freeze_time("2024-05-25")
    def test_not_near_date(self):
        with self.assertRaises(ValueError) as context:
            lambda_function.verify(
                {
                    "body": base64.encodebytes(gzip.compress(EXAMPLE_TQ8.encode()))
                },{}
            )
            self.assertEqual(context, "Log QSO dates too far out of range")


if __name__ == '__main__':
    unittest.main()