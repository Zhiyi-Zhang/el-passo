# basic
import sys
# web server
from flask import Flask, jsonify, request
# crypto
from charm.schemes.pksig.pksig_ps03 import PS01
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
import hashlib
import time

debug = False

grp = None
ps = None
pk = None
sk = None

credential_element_size = None

credential_issuing_start_tp = 0
counter = 0
pk_json = None

def ps_sign(user_commit, expires_in, gamma):
    user_commit = user_commit * (pk['Y1'][1] ** grp.hash(str(gamma), ZR))
    user_commit = user_commit * (pk['Y1'][2] ** grp.hash(str(expires_in), ZR))
    for i in range(credential_element_size):
        user_commit = user_commit * (pk['Y1'][3 + i] ** grp.hash(str(i) + 'th-element'))
    sig = ps.sign(sk, pk, user_commit)
    if debug:
        print("Signature: ", sig, flush=True)
    return sig


def app_main():
    app = Flask(__name__)

    # BOOTSTRAP: generate pp and pk,sk
    global grp, ps, pk, sk
    start = time.time()
    grp = PairingGroup('MNT224')
    ps = PS01(grp)
    end = time.time()
    print("CRED.Setup time elapse: {0}s ".format(str(end - start)), flush=True)

    # KEYGEN
    start = time.time()
    (pk, sk) = ps.keygen(3 + credential_element_size)  # messages format: [user_secret, gamma, expires_in]
    end = time.time()
    print("CRED.KeyGen over {0} attributes time elapse: {1}s ".format(str(3 + credential_element_size), str(end - start)), flush=True)
    if debug:
        print("Keygen...", flush=True)
        print("pk :=", pk, flush=True)
        print("sk :=", sk, flush=True)

    @app.route('/', methods=['GET', 'POST'])
    def index():
        global pk_json
        if pk_json is None:
            pk_serial = dict(pk)
            for key, value in pk_serial.items():
                if debug:
                    print(key)
                if key in {'X2', 'g1', 'g2'}:
                    pk_serial[key] = grp.serialize(value).decode()
                else:
                    pk_serial[key] = [grp.serialize(item).decode() for item in value]
            pk_json = jsonify(pk_serial)
        return pk_json

    @app.route('/token', methods=['GET', 'POST'])
    def token():
        # For the purpose of throughput measurement
        global credential_issuing_start_tp, counter
        if credential_issuing_start_tp == 0:
            credential_issuing_start_tp = time.time()
        print("IdP Throughput: {0}s for {1} credentials".format(str(time.time() - credential_issuing_start_tp),
                                                                 str(counter)))
        counter += 1

        # IdP logic starts here
        print("Credential request content length: ", request.content_length, flush=True)
        request_json = request.get_json()
        gt = grp.deserialize(request_json['g_t'].encode())
        a = grp.deserialize(request_json['a'].encode())
        pa = grp.deserialize(request_json['commitment_secret'].encode())
        r = grp.deserialize(request_json['r'].encode())

        # generate nb
        start = time.time()
        m = hashlib.sha256()
        m.update(grp.serialize(pk['Y1'][0]))
        m.update(grp.serialize(a))
        m.update(grp.serialize(pa))
        m.update(b'userid')  # replaced with real values
        nb = m.digest()
        nb = grp.hash(nb)
        # do the check
        lh = pk['Y1'][0] ** r
        rh = a * (pa ** nb)
        end = time.time()
        print("NIZK Schnorr verifier (User-IdP) over {0} "
              "attributes time elapse: {1}s ".format(str(1), str(end - start)), flush=True)
        if lh == rh:
            if debug:
                print('Successfully finish Schnorr protocol', flush=True)
            # Cred.Sign
            start = time.time()
            gamma = grp.random()
            user_commit = gt * pa
            user_id_token = ps_sign(user_commit, 3600 * 12 * 30, gamma)
            end = time.time()
            print("CRED.Sign over {0} attributes"
                  " time elapse: {1}s ".format(str(3 + credential_element_size), str(end - start)), flush=True)
            user_id_token = [grp.serialize(item).decode() for item in user_id_token]
            return jsonify(
                gamma=str(gamma),
                expires_in=str(3600 * 12 * 30),
                id_token=user_id_token,
            )
        else:
            if debug:
                print("lh:=", lh, flush=True)
                print('rh:=', rh, flush=True)
            return None

    app.run(host='0.0.0.0', port=6000, ssl_context='adhoc')


if __name__ == "__main__":
    if len(sys.argv) >= 2 and int(sys.argv[1].rstrip()) > 0:
        credential_element_size = int(sys.argv[1].rstrip())
    else:
        credential_element_size = 0
    app_main()
