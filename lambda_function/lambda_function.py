import sys
import base64
import gzip
import adif_io
import cryptography.x509
import os
import hashlib
import json
import datetime
import pyotp
import re
import urllib.request
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

SECRET = os.environ["SECRET"]
VERIFICATION_SIGDATA = "ZZ9FOTWFT8" # This is callsign ZZ9FOTW, mode FT8 

DAYS_VALID = 60 # this should be lower but I forgot javascript was 0 indexed for months. Once static content cache has been invalidated will change back

ca = cryptography.x509.load_pem_x509_certificate(open("ca.pem","rb").read())

if len(SECRET) < 10:
    raise ValueError("SECRET too small")

def verify(event, context):
    """
    Checks a log file to see if its correctly sign by a LoTW valid cert
    """
    data = base64.b64decode(event['body'])
    data = gzip.decompress(data).decode()
    data = "<eoh>\n"+data
    data = re.sub(r'(<SIGN_LOTW_V2)\.\d+(:\d+):\d+(>)',r'\1\2\3',data)
    qsos, headers = adif_io.read_from_string(data)
    

    if len(qsos) != 3:
        raise ValueError("Log contains too many records")
    for cert in qsos:
        if cert['REC_TYPE'] == 'tCERT':
            cert = "-----BEGIN CERTIFICATE-----\n" + cert['CERTIFICATE'] + "-----END CERTIFICATE-----"
            break
    else:
        raise ValueError("Did not find tCERT")
    for qso in qsos:
        if qso['REC_TYPE'] == 'tCONTACT':
            break
    else: # I know I shouldn't but I couldn't help myself
        raise ValueError("Did not find tCONTACT")

    # parsing and checking dates serves two purposes
    # making sure the signed log is recent and ensuring tampering of qso date/time isn't messing with SIGDATA
    qso_date = datetime.datetime.fromisoformat(qso['QSO_DATE']+"T"+qso['QSO_TIME'])

    if ( (qso_date < (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=DAYS_VALID))) or
         (qso_date > (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=DAYS_VALID)))
        ):
        raise ValueError("Log QSO dates too far out of range")

    if not qso['SIGNDATA'].endswith(VERIFICATION_SIGDATA+qso['QSO_DATE']+qso['QSO_TIME']):
        raise ValueError("Not matching sig")

    user = cryptography.x509.load_pem_x509_certificate(cert.encode())
    user.verify_directly_issued_by(ca)

    if ( datetime.datetime.now(datetime.timezone.utc) > user.not_valid_after_utc or
        datetime.datetime.now(datetime.timezone.utc) < user.not_valid_before_utc):
        raise ValueError("Cert time not valid")
    
    callsign = user.subject.get_attributes_for_oid(cryptography.x509.ObjectIdentifier("1.3.6.1.4.1.12348.1.1"))[0].value
    
    # WSJTX requires 16 base32 digits = 80 bits of data (5*16) = 10 bytes
    user_secret = hashlib.sha3_512((SECRET + callsign).encode()).digest()[:10]
    user_secret_b32 = base64.b32encode(user_secret)

    sig = qso['SIGN_LOTW_V2']

    user.public_key().verify(base64.b64decode(sig), qso['SIGNDATA'].encode(), padding.PKCS1v15(), hashes.SHA1())

    return {
        "body": json.dumps(
            {
                "callsign": callsign,
                "secret": user_secret_b32.decode()
            }),
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json"
        }
    }

def validate(event, context):
    """
    Checks if a callsign + OTP is valid for a timestamp
    """
    callsign = event["pathParameters"]["callsign"].upper()
    timestamp = event["pathParameters"]["timestamp"]
    code = event["pathParameters"]["code"].replace(".text","")
    timestamp_otp = datetime.datetime.fromisoformat(timestamp).timestamp()//30
    if timestamp_otp > datetime.datetime.now(datetime.timezone.utc).timestamp()//30:
        raise ValueError("Time in future")

    user_secret = hashlib.sha3_512((SECRET + callsign).encode()).digest()[:10]
    user_secret_b32 = base64.b32encode(user_secret)
    token = pyotp.HOTP(user_secret_b32).at(int(timestamp_otp))

    if token == code:
        return {
            "body": f"{callsign} VERIFIED",
            "statusCode": 200,
            "headers": {
                "Content-Type": "text/plain"
            }
        }
    else: # try to validate against https://www.9dx.cc
        try:
            contents = urllib.request.urlopen(f"https://www.9dx.cc/check/{callsign}/{timestamp}/{code}.text").read()
        except:
            contents = f"{callsign} UNVERIFIED"
        return {
            "body": contents,
            "statusCode": 200,
            "headers": {
                "Content-Type": "text/plain"
            }
        }