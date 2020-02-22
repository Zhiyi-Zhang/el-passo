from charm.schemes.pksig.pksig_ps03 import PS01
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
import time
import hashlib

def measure_time(attribute_num):
    # setup
    start = time.time()
    grp = PairingGroup('MNT224')
    ps = PS01(grp)
    end = time.time()
    print("Setup time elapse: ")
    print(end - start)

    # keygen
    start = time.time()
    (pk, sk) = ps.keygen(attribute_num)
    end = time.time()
    print("KeyGen over {0} attributes time elapse: {1}s ".format(str(attribute_num), str(end - start)))

    # generate a secret
    secret = grp.random()

    # NIZK Schnorr prover
    start = time.time()
    na = grp.random()
    a = pk['Y1'][0] ** na
    # deterministic nb
    m = hashlib.sha256()
    m.update(grp.serialize(pk['Y1'][0]))
    m.update(grp.serialize(a))
    m.update(grp.serialize(pk['Y1'][0] ** secret))
    m.update(b'userid')  # replaced with real values
    nb = m.digest()
    nb = grp.hash(nb)
    # r
    r = na + nb * secret
    end = time.time()
    print("NIZK Schnorr over {0} attributes Prover time elapse: {1}s".format(str(attribute_num), str((end - start)*attribute_num)))
    # NIZK Schnorr verifier
    start = time.time()
    m = hashlib.sha256()
    m.update(grp.serialize(pk['Y1'][0]))
    m.update(grp.serialize(a))
    m.update(grp.serialize(pk['Y1'][0] ** secret))
    m.update(b'userid')  # replaced with real values
    nb = m.digest()
    nb = grp.hash(nb)
    lh = pk['Y1'][0] ** r
    rh = a * (pk['Y1'][0] ** secret) ** nb
    end = time.time()
    print("NIZK Schnorr over {0} attributes Verifier time elapse: {1}s".format(str(attribute_num), str((end - start)*attribute_num)))
    if lh == rh:
        print('NIZK check success')
    else:
        print('NIZK check failure')

    # request ID
    messages = ["hello" + str(i) for i in range(0, attribute_num)]
    start = time.time()
    t, commitment = ps.commitment(pk, *messages)
    end = time.time()
    print("requestID over {0} attributes time elapse: {1}s".format(str(attribute_num), str(end - start)))

    # prove ID
    start = time.time()
    sig = ps.sign(sk, pk, commitment)
    end = time.time()
    print("ProvideID over {0} attributes time elapse: {1}s".format(str(attribute_num), str(end - start)))

    # unblind signature
    start = time.time()
    sig = ps.unblind_signature(t, sig)
    end = time.time()
    print("Unblind over {0} attributes time elapse: {1}s".format(str(attribute_num), str(end - start)))

    # prove ID
    start = time.time()
    rand_sig = ps.randomize_sig(sig)
    cipher_sk = grp.random()
    cipher_1 = pk['Y2'][1] ** cipher_sk
    cipher_pk = (pk['Y2'][1] ** grp.hash('authority')) ** cipher_sk
    cipher_2 = cipher_pk * (pk['Y2'][0] ** grp.hash(messages[0], ZR))
    end = time.time()
    print("Credential Randomize over {0} attributes time elapse: {1}s".format(str(attribute_num), str(end - start)))

    # cred.verify
    start = time.time()
    result = ps.verify(pk, rand_sig, *messages)
    end = time.time()
    print("RP's Credential Verify over {0} attributes time elapse: {1}s".format(str(attribute_num), str(end - start)))

def schnorr_NIZK():
    # setup
    start = time.time()
    grp = PairingGroup('MNT224')
    ps = PS01(grp)
    end = time.time()
    print("Setup time elapse: ")
    print(end - start)
    # keygen
    start = time.time()
    (pk, sk) = ps.keygen(2)
    end = time.time()
    print("KeyGen over two attributes time elapse: ")
    print(end - start)
    # generate a secret
    secret = grp.random()
    # NIZK Schnorr prover
    start = time.time()
    na = grp.random()
    a = pk['Y1'][0] ** na
    # deterministic nb
    m = hashlib.sha256()
    m.update(grp.serialize(pk['Y1'][0]))
    m.update(grp.serialize(a))
    m.update(grp.serialize(pk['Y1'][0] ** secret))
    m.update(b'userid') # replaced with real values
    nb = m.digest()
    nb = grp.hash(nb)
    # r
    r = na + nb * secret
    end = time.time()
    print("NIZK Schnorr on one attribute Prover time elapse: ")
    print(end - start)
    # NIZK Schnorr verifier
    start = time.time()
    m = hashlib.sha256()
    m.update(grp.serialize(pk['Y1'][0]))
    m.update(grp.serialize(a))
    m.update(grp.serialize(pk['Y1'][0] ** secret))
    m.update(b'userid')  # replaced with real values
    nb = m.digest()
    nb = grp.hash(nb)
    lh = pk['Y1'][0] ** r
    rh = a * (pk['Y1'][0] ** secret) ** nb
    end = time.time()
    print("NIZK Schnorr Verifier time elapse: ")
    print(end - start)
    if lh == rh:
        print('check success')
    else:
        print('lh:=', lh)
        print('rh:=', rh)

def schnorr_protocol_y_instead_of_g():
    grp = PairingGroup('MNT224')
    ps = PS01(grp)
    (pk, sk) = ps.keygen(2)
    secret = grp.random()
    # A
    na = grp.random()
    a = pk['Y1'][0] ** na
    # B
    nb = grp.random()
    # A
    r = na + nb * secret
    # B
    lh = pk['Y1'][0]  ** r
    rh = a * (pk['Y1'][0] ** secret) ** nb
    if lh == rh:
        print('check success')
    else:
        print('lh:=', lh)
        print('rh:=', rh)

def schnorr_protocol():
    grp = PairingGroup('MNT224')
    ps = PS01(grp)
    (pk, sk) = ps.keygen(2)
    t = grp.random()
    # A
    na = grp.random()
    a = pk['g2'] ** na
    # B
    nb = grp.random()
    # A
    r = na + nb * t
    # C
    lh = pk['g2'] ** r
    rh = a * (pk['g2'] ** t) ** nb
    if lh == rh:
        print('check success')
    else:
        print('lh:=', lh)
        print('rh:=', rh)

def test_ps_sign_schnorr():
    grp = PairingGroup('MNT224')
    ps = PS01(grp)

    messages = ["hi there"]
    (pk, sk) = ps.keygen(len(messages) + 1)
    if debug:
        print("Keygen...")
        print("pk :=", pk)
        print("sk :=", sk)

    t, commitment = ps.commitment(pk, *messages)
    # append public information
    commitment = commitment * (pk['Y1'][-1] ** grp.hash('3600', ZR))

    if debug:
        print("commitment: ", commitment)

    be_signed = commitment
    sig = ps.sign(sk, pk, commitment)
    if debug:
        print("Signature: ", sig)

    sig = ps.unblind_signature(t, sig)
    # append public information
    messages.append('3600')
    result = ps.verify(pk, sig, *messages)
    assert result, "INVALID signature!"
    if debug:
        print("Successful Verification!!!")

    # sec6.2 randomize
    s1, s2 = sig
    t = grp.random(ZR)
    r = grp.random(ZR)
    s1p = s1**r
    s2p = (s2*(s1**t))**r

    # sec6.2 verify
    lh = pair(s1p, pk['X2'])
    lh = lh * ps.product([pair(s1p, y**grp.hash(m, ZR)) for y, m in zip(pk['Y2'], messages)])
    lh = lh * pair(s1p, pk['g2']**t)
    rh = pair(s2p, pk['g2'])
    if lh == rh:
        print('check success')
    else:
        print('lh:=', lh)
        print('rh:=', rh)

def test_ps_sign_with_public_info():
    # setup
    start = time.time()
    grp = PairingGroup('MNT224')
    ps = PS01(grp)
    end = time.time()
    print("Setup time elapse: ")
    print(end - start)

    # messages = ['Hi there', 'Not there', 'Some message ................', 'Dont know .............', 'great!!!!']
    messages = ["hi there"]
    # keygen
    start = time.time()
    (pk, sk) = ps.keygen(len(messages) + 1)
    end = time.time()
    print("KeyGen time elapse: ")
    print(end - start)
    if debug:
        print("Keygen...")
        print("pk :=", pk)
        print("sk :=", sk)

    # requestID
    start = time.time()
    t, commitment = ps.commitment(pk, *messages)
    end = time.time()
    print("requestID time elapse: ")
    print(end - start)

    # append public information
    start = time.time()
    commitment = commitment * (pk['Y1'][-1] ** grp.hash('3600', ZR))
    sig = ps.sign(sk, pk, commitment)
    end = time.time()
    print("ProvideID time elapse: ")
    print(end - start)

    if debug:
        print("commitment: ", commitment)
    if debug:
        print("Signature: ", sig)

    # unblind signature
    start = time.time()
    sig = ps.unblind_signature(t, sig)
    end = time.time()
    print("Unblind time elapse: ")
    print(end - start)

    # append public information
    messages.append('3600')
    result = ps.verify(pk, sig, *messages)
    assert result, "INVALID signature!"
    if debug:
        print("Successful Verification!!!")

    # prove ID
    start = time.time()
    rand_sig = ps.randomize_sig(sig)
    end = time.time()
    print("Credential Randomize time elapse: ")
    print(end - start)

    assert sig != rand_sig
    if debug:
        print("Randomized Signature: ", rand_sig)

    # cred.verify
    start = time.time()
    result = ps.verify(pk, rand_sig, *messages)
    end = time.time()
    print("RP's Credential Verify time elapse: ")
    print(end - start)

    assert result, "INVALID signature!"
    if debug:
        print("Successful Verification!!!")

def test_ps_sign():
    grp = PairingGroup('MNT224')
    ps = PS01(grp)

    # messages = ['Hi there', 'Not there', 'Some message ................', 'Dont know .............', 'great!!!!']
    messages = ["hi there"]
    (pk, sk) = ps.keygen(20)
    if debug:
        print("Keygen...")
        print("pk :=", pk)
        print("sk :=", sk)
    pk_len = 0
    sk_len = 0
    pk_serial = dict(pk)
    sk_serial = dict(sk)
    for key, value in sk_serial.items():
        sk_serial[key] = grp.serialize(value).decode()
    for key, value in pk_serial.items():
        if key in {'X2', 'g1', 'g2'}:
            pk_serial[key] = grp.serialize(value).decode()
        else:
            pk_serial[key] = [grp.serialize(item).decode() for item in value]
    for key, value in pk_serial.items():
        if key in {'X2', 'g1', 'g2'}:
            pk_len += len(pk_serial[key])
        else:
            for item in pk_serial[key]:
                pk_len += len(item)
    for key, value in sk_serial.items():
        sk_len += len(sk_serial[key])

    print('public key bytes: ', str(pk_len))
    print('private key bytes: ', str(sk_len))

    t = grp.random()
    print(t)
    print('random number len')
    print(len(grp.serialize(t).decode()))
    zeta = grp.random(G1)
    zeta = zeta ** t
    print(zeta)
    print('group element len')
    print(len(grp.serialize(zeta).decode()))

    t, commitment = ps.commitment(pk, *messages)

    if debug:
        print("commitment: ", commitment)

    be_signed = commitment
    sig = ps.sign(sk, pk, commitment)
    if debug:
        print("Signature: ", sig)

    sig = ps.unblind_signature(t, sig)
    print(len(grp.serialize(sig[0]).decode()))
    print(len(grp.serialize(sig[1]).decode()))

    result = ps.verify(pk, sig, *messages)
    assert result, "INVALID signature!"
    if debug:
        print("Successful Verification!!!")

    rand_sig = ps.randomize_sig(sig)
    assert sig != rand_sig
    if debug:
        print("Randomized Signature: ", rand_sig)

    result = ps.verify(pk, rand_sig, *messages)
    assert result, "INVALID signature!"
    if debug:
        print("Successful Verification!!!")

def test_speed_of_idp_user_lookup():
    grp = PairingGroup('MNT224')
    h = grp.hash('yelp', G1)
    start = time.time()
    for i in range(0, 100000):
        r = grp.random()
        result = h ** r
    end = time.time()
    print("Time for IdP to look up a user's gamma among 100k users: ")
    print(end-start)

def test_batch_function():
    grp = PairingGroup('MNT224')
    g1 = grp.hash('g1', G1)
    g2 = grp.hash('g2', G1)
    h1 = grp.hash('h1', G2)
    h2 = grp.hash('h2', G2)
    h3 = grp.hash('h3', G2)
    start = time.time()
    lhs = pair(g1, h1) * pair(g1, h2) * pair(g1, h3) * pair(g2, h1)
    end = time.time()
    print(F'total time for un-batched: {end - start}')
    start = time.time()
    rhs = pair(g1, h1*h2*h3) * pair(g2, h1)
    end = time.time()
    print(F'total time for batched: {end - start}')
    if lhs == rhs:
        print('success')
    else:
        print('fail')


if __name__ == "__main__":
    debug = True
    test_batch_function()
    #test_ps_sign_with_public_info()
    #schnorr_protocol()
    #test_ps_sign_schnorr()
    #schnorr_protocol_y_instead_of_g()
    #test_speed_of_idp_user_lookup()
    #schnorr_NIZK()
    #test_ps_sign_with_public_info()
    #measure_time(5)