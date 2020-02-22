import sys
# http client
import aiohttp
import asyncio
# crypto
from charm.schemes.pksig.pksig_ps03 import PS01
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
import hashlib
import time

debug = False
hidden_elements = 0
idp_ip = '0.0.0.0'
rp_ip = '127.0.0.1'
running_frequency = 1

# crypto global variables
grp = None
pk = None
ps = None
secret = None
gamma = None
expires_in = None
messages = None
sig = None

def generate_params_for_RP():
    # preparation: randomize sig as sec 6.2 of PS paper
    start = time.time()
    s1, s2 = sig
    proof_t = grp.random(ZR)
    proof_r = grp.random(ZR)
    s1p = s1 ** proof_r
    s2p = (s2 * (s1 ** proof_t)) ** proof_r
    rand_sig = s1p, s2p
    end = time.time()
    print("CRED.Randomize time elapse: {0}s ".format(str(end - start)))

    rand_sig_json = [grp.serialize(item).decode() for item in rand_sig]

    # generate a pub key for El Gamal cipher text
    start = time.time()
    cipher1_rand = grp.random(ZR)
    gamma_base = grp.hash('random1', G1)  # this gamma_base is public known
    cipher1_base = grp.hash('random2', G1)  # this cipher1_base is known to User and RP, but not to IdP
    # c = (g^k, y^k h_1^gamma)
    cipher_1 = cipher1_base ** cipher1_rand
    authority_pk = pk['g1'] ** grp.hash('authority')  # one should only know authority_pk as a whole
    cipher_2_1 = authority_pk ** cipher1_rand
    cipher_2_2 = gamma_base ** gamma
    cipher_2 = cipher_2_1 * cipher_2_2
    end = time.time()
    print("Prepare ciphertext as the user id time elapse: {0}s".format(str(end - start)))

    # first rt: schnorr NIZK + PS signature section 6.2 proof of knowledge
    base = [
        pk['g2'],  # for random number
        grp.hash('domain', G1),  # for user id at RP
        cipher1_base,  # for El Gamal cipher 1
        authority_pk,  # for El Gamal cipher 2
        gamma_base,  # for El Gamal cipher 2
        pk['Y2'][0],  # for secret
        pk['Y2'][1],  # for gamma
    ]
    for i in range(3, 3 + hidden_elements):
        base.append(pk['Y2'][i])
    rp_schnorr_nas = [grp.random() for i in range(0, len(base))]

    start = time.time()
    rp_schnorr_pas = [
        base[0] ** proof_t,  # t
        base[1] ** secret,  # secret, for user id at RP
        cipher_1,
        cipher_2_1,
        cipher_2_2,
        base[5] ** secret,  # secret
        base[6] ** gamma,  # gamma
    ]
    for i in range(hidden_elements):
        rp_schnorr_pas.append(base[7 + i] ** grp.hash(messages[3 + i], ZR))  # extra elements
    rp_schnorr_as = [
        base[0] ** rp_schnorr_nas[0],  # for random number
        base[1] ** rp_schnorr_nas[1],  # for user id at RP
        base[2] ** rp_schnorr_nas[2],  # for El Gamal cipher 1
        base[3] ** rp_schnorr_nas[3],  # for El Gamal cipher 2
        base[4] ** rp_schnorr_nas[4],  # for El Gamal cipher 2
        base[5] ** rp_schnorr_nas[5],  # for secret
        base[6] ** rp_schnorr_nas[6],  # for gamma
    ]
    for i in range(hidden_elements):
        rp_schnorr_as.append(base[7 + i] ** rp_schnorr_nas[7 + i])
    # generate nbs
    m = hashlib.sha256()
    m.update(grp.serialize(base[0]))
    m.update(grp.serialize(rp_schnorr_as[0]))
    m.update(grp.serialize(rp_schnorr_pas[0]))
    m.update(b'userid')  # replaced with real values
    nb = m.digest()
    nb = grp.hash(nb)
    # generate rs
    rp_schnorr_rs = [
        rp_schnorr_nas[0] + nb * proof_t,
        rp_schnorr_nas[1] + nb * secret,
        rp_schnorr_nas[2] + nb * cipher1_rand,
        rp_schnorr_nas[3] + nb * cipher1_rand,
        rp_schnorr_nas[4] + nb * gamma,
        rp_schnorr_nas[5] + nb * secret,
        rp_schnorr_nas[6] + nb * gamma,
    ]
    for i in range(hidden_elements):
        rp_schnorr_rs.append(rp_schnorr_nas[7 + i] + nb * grp.hash(messages[3 + i], ZR))
    end = time.time()
    print("NIZK Schnorr Prover (User-RP) over {0} elements time elapse: {1}s ".format(str(4 + hidden_elements),
                                                                                      str(end - start)))

    json_param = {
        'additional_element_num': str(hidden_elements),
        'g2_t': grp.serialize(rp_schnorr_pas[0]).decode(),
        'user_id': grp.serialize(rp_schnorr_pas[1]).decode(),
        'el_cipher_1': grp.serialize(cipher_1).decode(),
        'el_cipher_2': grp.serialize(cipher_2).decode(),
        'commitment_secret': grp.serialize(rp_schnorr_pas[5]).decode(),
        'commitment_gamma': grp.serialize(rp_schnorr_pas[6]).decode(),

        'g2_t_a': grp.serialize(rp_schnorr_as[0]).decode(),
        'user_id_a': grp.serialize(rp_schnorr_as[1]).decode(),
        'el_cipher_1_a': grp.serialize(rp_schnorr_as[2]).decode(),
        'el_cipher_2_a': grp.serialize(rp_schnorr_as[3] * rp_schnorr_as[4]).decode(),
        'commitment_secret_a': grp.serialize(rp_schnorr_as[5]).decode(),
        'commitment_gamma_a': grp.serialize(rp_schnorr_as[6]).decode(),

        'g2_t_r': grp.serialize(rp_schnorr_rs[0]).decode(),
        'user_id_r': grp.serialize(rp_schnorr_rs[1]).decode(),
        'el_cipher_1_r': grp.serialize(rp_schnorr_rs[2]).decode(),
        'el_cipher_2_r1': grp.serialize(rp_schnorr_rs[3]).decode(),
        'el_cipher_2_r2': grp.serialize(rp_schnorr_rs[4]).decode(),
        'commitment_secret_r': grp.serialize(rp_schnorr_rs[5]).decode(),
        'commitment_gamma_r': grp.serialize(rp_schnorr_rs[6]).decode(),

        'rand_sig': rand_sig_json,
        'expires_in': expires_in,
    }
    for i in range(hidden_elements):
        json_param.update({str(i) + 'th-pa': grp.serialize(rp_schnorr_pas[7 + i]).decode()})
        json_param.update({str(i) + 'th-a': grp.serialize(rp_schnorr_as[7 + i]).decode()})
        json_param.update({str(i) + 'th-r': grp.serialize(rp_schnorr_rs[7 + i]).decode()})
    if debug:
        print(json_param)
    return json_param


async def fetch(session, url, json_param=None):
    async with session.get(url, json=json_param) as response:
        print("response content length: ", response.headers['Content-Length'])
        return await response.json()


async def main():
    # group setup and secret generation
    setup_start_time = time.time()
    global grp, ps, pk, secret, messages, sig, gamma, expires_in
    grp = PairingGroup('MNT224')
    messages = ['random_string']
    secret = grp.hash(messages[0], ZR)
    ps = PS01(grp)
    pk = None
    setup_end_time = time.time()
    print("Setup total time: {0}s ".format(str(setup_end_time - setup_start_time)))
    # communicate with IdP
    print("****Communication with IdP****")
    idp_start_time = time.time()
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        # first rt: get idp public key
        pk = await fetch(session, 'https://' + idp_ip + ':6000/')
        for key, value in pk.items():
            if key in {'X2', 'g1', 'g2'}:
                pk[key] = grp.deserialize(value.encode())
            else:
                pk[key] = [grp.deserialize(item.encode()) for item in value]
        if debug:
            print('idp pk:=', pk)

        # generate t and commitment
        start = time.time()
        t = grp.random(ZR)
        gt = (pk['g1'] ** t)
        commitment_secret = pk['Y1'][0] ** secret
        commitment = gt * commitment_secret
        if debug:
            print("commitment: ", commitment)
        end = time.time()
        print("CRED.PrepareBlindSign over {0} attributes time elapse: {1}s ".format(str(1), str(end - start)))

        # second rt: schnorr proof
        start = time.time()
        na = grp.random()
        a = pk['Y1'][0] ** na
        # schnorr NIZK: generate nb
        m = hashlib.sha256()
        m.update(grp.serialize(pk['Y1'][0]))
        m.update(grp.serialize(a))
        m.update(grp.serialize(pk['Y1'][0] ** secret))
        m.update(b'userid')  # replaced with real values
        nb = m.digest()
        nb = grp.hash(nb)
        r = na + nb * secret
        end = time.time()
        print("NIZK Schnorr Prover (User-IdP) over {0} element time elapse: {1}s ".format(str(1), str(end - start)))

        json_param = {'g_t': grp.serialize(gt).decode(),
                      'commitment_secret': grp.serialize(commitment_secret).decode(),
                      'a': grp.serialize(a).decode(),
                      'r': grp.serialize(r).decode()}
        json_rep = await fetch(session, 'https://' + idp_ip + ':6000/token', json_param)
        # parse the reply
        id_token = json_rep['id_token']
        id_token = [grp.deserialize(item.encode()) for item in id_token]
        expires_in = json_rep['expires_in']
        gamma = json_rep['gamma']
        if debug:
            print('user id token:=', id_token)
            print('expires_in:=', expires_in)
            print('gamma:=', gamma)

        # unblind signature
        start = time.time()
        sig = ps.unblind_signature(t, id_token)
        end = time.time()
        print("CRED.Unblind time elapse: {0}s ".format(str(end - start)))
        messages.append(gamma)
        messages.append(expires_in)
        for i in range(3, len(pk['Y1'])):
            messages.append(str(i - 3) + 'th-element')
        if debug:
            print(messages)
            result = ps.verify(pk, sig, *messages)
            assert result, 'invalid signature'
            print('Successfully verification')
        gamma = grp.hash(gamma, ZR)
    idp_end_time = time.time()
    print("IdP total time: {0}s ".format(str(idp_end_time - idp_start_time)))

    # communicate with RP

    print("\n****Communication with RP****")
    rp_start_time = time.time()
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        json_param = generate_params_for_RP()

        average_time = 0
        counter = 0
        for i in range(0, 20):
            time1 = time.time()
            json_rep = await fetch(session, 'https://' + rp_ip + ':6001/authenticate', json_param)
            time2 = time.time()
            counter += 1
            average_time += (time2 - time1)
            if 1 - (time2 - time1) > 0:
                time.sleep(1 - (time2 - time1))

        print("average time per credential: ", str(average_time / counter))

    rp_end_time = time.time()
    print("RP total time: {0}s ".format(str(rp_end_time - rp_start_time)))


if __name__ == '__main__':
    #useage: python3 user.py idp_IP rp_IP hide_additional_element_num
    if len(sys.argv) >= 3:
        print("assigning idp and rp_ip")
        idp_ip = sys.argv[1]
        rp_ip = sys.argv[2]

    if len(sys.argv) >= 4:
        running_frequency = float(sys.argv[3].rstrip())
    
    loop = asyncio.get_event_loop()
    start = time.time()

    loop.run_until_complete(main())
    end = time.time()
    print("total time observed by the user: {0}s".format(str(end - start)))
