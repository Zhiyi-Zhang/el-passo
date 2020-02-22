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
        average_time = 0
        counter = 0
        for i in range(0, 20):
            time1 = time.time()
            print(time.time())
            json_rep = await fetch(session, 'https://' + idp_ip + ':6000/token', json_param)
            time2 = time.time()
            counter += 1
            average_time += (time2 - time1)
            if 1/running_frequency - (time2 - time1) > 0:
                time.sleep(1/running_frequency - (time2 - time1))
    print("average time per credential: ", str(average_time/counter))
    idp_end_time = time.time()
    print("IdP total time: {0}s ".format(str(idp_end_time - idp_start_time)))


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
