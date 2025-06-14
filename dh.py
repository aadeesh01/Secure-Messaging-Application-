def generate_dh_keys(p, g):
    private_key = 6
    public_key = pow(g, private_key, p)
    return private_key, public_key

def compute_shared_key(pub, priv, p):
    return pow(pub, priv, p)