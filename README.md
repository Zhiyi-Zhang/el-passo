# EL PASSO

We currently have Python3 implementation of IdP (sso-idp), RP (sso-rp), user app(sso-user) and user Firefox plugin (sso-plugin).

## Requirements
To run the example you need Python3, flask and charm
To install flask, run
```
pip install flask
```

To install charm clone their git repository and install the project:
```
git clone https://github.com/JHUISI/charm
cd charm
cd deps
make
cd ..
./configure.sh
make install
make test
```

The Firefox plugin must can be teporarily installed using debugging interface. Open Firefox and type `about:debugging` in the address bar. Then choose `Load Temporary Add-on` and navigate to `sso-plugin/manifest.json` file.

## Running
To run the examples  1. run idp 2. run RP, 3. run user.

### IdP
```
cd sso-idp
python3 idp.py additional_element_num
```

The argument `additional_element_num` is optional, when not specified, the credential is by default issued over three elements.
1. random number, called secret, which is user's secret
2. random number, called gamma, which is a secret known to IdP and User
3. unsigned number, called expires_in which indicate the validity period of the credential.

Under real world settings, it is possible to have additional elements covered by the credential, e.g., user's email address, user ID, social media account name, etc.
In this case, the argument `additional_element_num` is to indicate how many additional elements are there.
For example, `python3 idp.py 2` will let the IdP to sign the credential over `3 + 2` elements, which in our prototype imple are:
1. random number, called secret, which is user's secret
2. random number, called gamma, which is a secret known to IdP and User
3. unsigned number, called expires_in which indicate the validity period of the credential.
4. '0th-element'
5. '1th-element'


### RP
```
cd sso-rp
python3 rp.py
```

### User
```
cd sso-rp
python3 rp.py IdP_IP RP_IP hidden_element_num
```

The argument `hidden_element_num` is to tell the user client how many elements should be hidden from a RP.
This argument must be smaller than `additional_element_num`.
For example, if `additional_element_num`=5, the credential is signed over 3 basic elements and:
* '0th-element'
* '1th-element'
* '2th-element'
* '3th-element'
* '4th-element'
When `hidden_element_num`=0, all five additional elements will be shown to the RP in plaintext.
When `hidden_element_num`=2, the first two elements will be hidden from the RP; instead, the user will zero knowledge prove the possession of these two elements.