import sys
# web client
import requests
# web server
from flask import Flask, jsonify, render_template, request
# crypto
from charm.schemes.pksig.pksig_ps03 import PS01
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
import hashlib
import time

debug = False
idp_ip = '0.0.0.0'

schnorr_pas = None
schnorr_as = None
schnorr_nbs = None

user_auth_start_tp = 0
counter = 0

def app_main():
    app = Flask(__name__, template_folder="templates")

    # parameters
    grp = PairingGroup('MNT224')
    ps = PS01(grp)

    # get idp public key
    pk = requests.get('https://' + idp_ip + ':6000/', verify=False).json()
    for key, value in pk.items():
        if key in {'X2', 'g1', 'g2'}:
            pk[key] = grp.deserialize(value.encode())
        else:
            pk[key] = [grp.deserialize(item.encode()) for item in value]
    if debug:
        print('idp pk:=', pk, flush=True)

    @app.route('/authenticate', methods=['GET', 'POST'])
    def authenticate():
        # For the purpose of throughput measurement
        global user_auth_start_tp, counter
        if user_auth_start_tp == 0:
            user_auth_start_tp = time.time()
        print("RP Throughput: {0}s for {1} authentications".format(str(time.time() - user_auth_start_tp),
                                                                   str(counter)))
        counter += 1

        print("Authentication request content length: ", request.content_length, flush=True)
        authenticate_request = request.get_json()
        # first finish the Schnorr verification
        hidden_element_num = int(authenticate_request['additional_element_num'])
        schnorr_pas = [
            grp.deserialize(authenticate_request['g2_t'].encode()),
            grp.deserialize(authenticate_request['user_id'].encode()),
            grp.deserialize(authenticate_request['commitment_secret'].encode()),
            grp.deserialize(authenticate_request['commitment_gamma'].encode()),
        ]
        cipher_1 = grp.deserialize(authenticate_request['el_cipher_1'].encode())
        cipher_2 = grp.deserialize(authenticate_request['el_cipher_2'].encode())
        schnorr_as = [
            grp.deserialize(authenticate_request['g2_t_a'].encode()),
            grp.deserialize(authenticate_request['user_id_a'].encode()),
            grp.deserialize(authenticate_request['commitment_secret_a'].encode()),
            grp.deserialize(authenticate_request['commitment_gamma_a'].encode()),
        ]
        cipher_1_a = grp.deserialize(authenticate_request['el_cipher_1_a'].encode())
        cipher_2_a = grp.deserialize(authenticate_request['el_cipher_2_a'].encode())
        schnorr_rs = [
            grp.deserialize(authenticate_request['g2_t_r'].encode()),
            grp.deserialize(authenticate_request['user_id_r'].encode()),
            grp.deserialize(authenticate_request['commitment_secret_r'].encode()),
            grp.deserialize(authenticate_request['commitment_gamma_r'].encode()),
        ]
        cipher_1_r = grp.deserialize(authenticate_request['el_cipher_1_r'].encode())
        cipher_2_r1 = grp.deserialize(authenticate_request['el_cipher_2_r1'].encode())
        cipher_2_r2 = grp.deserialize(authenticate_request['el_cipher_2_r2'].encode())
        schnorr_bases = [
            pk['g2'],
            grp.hash('domain', G1),
            pk['Y2'][0],
            pk['Y2'][1],
        ]
        for i in range(hidden_element_num):
            schnorr_pas.append(grp.deserialize(authenticate_request[str(i) + 'th-pa'].encode()))
            schnorr_as.append(grp.deserialize(authenticate_request[str(i) + 'th-a'].encode()))
            schnorr_rs.append(grp.deserialize(authenticate_request[str(i) + 'th-r'].encode()))
            schnorr_bases.append(pk['Y2'][3 + i])
        if debug:
            print("Schnorr PAs: ")
            print(schnorr_pas)
            print("Schnorr As: ")
            print(schnorr_as)
            print("Schnorr Rs: ")
            print(schnorr_rs)
        # generate nbs
        start = time.time()
        m = hashlib.sha256()
        m.update(grp.serialize(schnorr_bases[0]))
        m.update(grp.serialize(schnorr_as[0]))
        m.update(grp.serialize(schnorr_pas[0]))
        m.update(b'userid')  # replaced with real values
        nb = m.digest()
        nb = grp.hash(nb)

        schnorr_result = True
        for i in range(len(schnorr_pas)):
            lh = schnorr_bases[i] ** schnorr_rs[i]
            rh = schnorr_as[i] * schnorr_pas[i] ** nb
            schnorr_result = (schnorr_result and (lh == rh))
            if debug and schnorr_result is False:
                print(i)
        # ciphertext 1
        lh = grp.hash('random2', G1) ** cipher_1_r
        rh = cipher_1_a * cipher_1 ** nb
        schnorr_result = (schnorr_result and (lh == rh))
        # ciphertext 2
        authority_pk = pk['g1'] ** grp.hash('authority')
        lh = (authority_pk ** cipher_2_r1) * (grp.hash('random1', G1) ** cipher_2_r2)
        rh = cipher_2_a * cipher_2 ** nb
        schnorr_result = (schnorr_result and (lh == rh))
        end = time.time()
        print("NIZK Schnorr Verifier (User-RP) over {0} element time elapse: {1}s ".format(str(len(schnorr_pas) + 2),
                                                                                           str(end - start)), flush=True)
        if schnorr_result is True:
            if debug:
                print('schnorr checking succeeds', flush=True)
        else:
            if debug:
                print('schnorr checking fails', flush=True)
            return jsonify(
                status='failure'
            )

        # PS signature proof
        start = time.time()
        rand_sig = [grp.deserialize(item.encode()) for item in authenticate_request['rand_sig']]
        expires_in = authenticate_request['expires_in']
        s1p, s2p = rand_sig
        messages = [schnorr_pas[2], schnorr_pas[3], pk['Y2'][2]**grp.hash(expires_in, ZR)]
        for i in range(hidden_element_num):
            messages.append(schnorr_pas[4 + i])
        for i in range(3 + hidden_element_num, len(pk['Y2'])):
            messages.append(pk['Y2'][i]**grp.hash(str(i - 3)+'th-element'))
        lh = pair(s1p, pk['X2'])
        lh = lh * ps.product([pair(s1p, m) for m in messages])
        lh = lh * pair(s1p, schnorr_pas[0])

        # lh_2 = pk['X2']
        # for m in messages:
        #     lh_2 = lh_2 * m
        # lh_2 = lh_2 * schnorr_pas[0]
        # lh = pair(s1p, lh_2)
        rh = pair(s2p, pk['g2'])
        end = time.time()
        print("Cred.Verify over {0} element time elapse: {1}s ".format(str(len(pk['Y2'])), str(end - start)), flush=True)
        if lh == rh:
            if debug:
                print('PS proof check succeeds', flush=True)
            return jsonify(
                status='success'
            )
        else:
            if debug:
                print('PS proof check fails', flush=True)
                print('lh:=', lh, flush=True)
                print('rh:=', rh, flush=True)
            return jsonify(
                status='failure'
            )

    app.run(host='0.0.0.0', port=6001, ssl_context='adhoc')

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        idp_ip = sys.argv[1]
    app_main()
