import hashlib, hmac

def generate_hmac(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()

def verify_hmac(key, data, mac):
    computed = hmac.new(key, data, hashlib.sha256).digest()
    return computed == mac