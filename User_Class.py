#!/usr/bin/env python3
from PythonClasses.bidict_Class import bidict
import PythonClasses.Number_Package as npkg

from PythonClasses.DES_Class import DES

from PythonClasses.Blum_Goldwessar_Class import BG
# from PythonClasses.ECC_Class import ECC
from PythonClasses.RSA_Class import RSA

from PythonClasses.User_Info_DB_Class import User_Info_DB

from PythonClasses.SHA1_Class import SHA1

import PythonClasses.Constants as Constants
import time
import re

import numpy as np


class User(object):
    """docstring for User."""
    def __init__(self, user_id=-1):
        # super(User, self).__init__()
        if user_id > 1 and user_id < Constants.USER_ID_MAX:
            self.user_id = user_id
        else:
            self.user_id = np.random.randint(1, Constants.USER_ID_MAX)
            print("user_id is set to be ", self.user_id)
        self.PKC_obj = None                     # chosen from RSA, ECC and BG
        self.SymmEnc_obj = None                 # currently, DES only
        self.sign_obj = RSA()
        self.public_key = self.sign_obj.get_public_key()              # public key for check
        self.cert = None
        self.cert_update()
        # self.PKG_TYPE_ID_DICT = Constants.PKG_TYPE_ID_DICT  # Package id - package funcionality
        # self.PKG_INFO_ITEMS = Constants.PKG_STRUCT_DICT             # structure of each type of package
        # self.ERROR_CODES = Constants.ERROR_CODE_DICT        # ErrorCode - description
        # self.ENCRYPT_ID_DICT = Constants.ENCRYPT_ID_DICT    # encryption - id
        # self.PKG_INFO_ITEMS = Constants.PKG_INFO_ITEMS              # list of items in the package
        # self.user_state = -1
        self.User_Info_DB = User_Info_DB()              # an object storing (userid: User_info )
        self.delimiter = Constants.DELIMITER            #


    """
    pkg_gen()
    ==============================================
    A function is to generate the package to send

    inputs:
      pkg_info: a dictionary containing nessary informations say: PKG_TYPE_ID, SRC_ID, MSG, etc

    outputs:
        pkg_msg_lst: a list of strings to be sent (even if usually there is only one object in the list)
    """
    def pkg_gen(self, pkg_info):
        PKG_TYPE_ID = pkg_info["PKG_TYPE_ID"]
        PKG_DESC = Constants.PKG_TYPE_ID_DICT.inverse[PKG_TYPE_ID][0]
        print(PKG_DESC)
        if PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["HELLO_MSG"]:
            # pkg_info["PKG_DESC"] = "HELLO_MSG"
            # pkg_info["SRC_ID"] = pkg_msg_list[2]
            # pkg_info["NEGO_PARAMS"] = Constants.DELIMITER.join(pkg_msg_list[3:])

            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            SRC_ID=pkg_info["SRC_ID"],\
            PUBLIC_KEY=pkg_info["PUBLIC_KEY"],\
            NEGO_PARAMS=pkg_info["NEGO_PARAMS"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["ACK_CERT"]:
            # pkg_info["PKG_DESC"] = "ACK_CERT"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["DST_ID"] = pkg_msg_list[3]
            # pkg_info["CERT"] = Constants.DELIMITER.join(pkg_msg_list[4:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=pkg_info["HMAC"],\
            DST_ID=pkg_info["DST_ID"],\
            PUBLIC_KEY=pkg_info["PUBLIC_KEY"],\
            CERT=pkg_info["CERT"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DNY_MSG"]:
            # pkg_info["PKG_DESC"] = "DNY_MSG"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=pkg_info["HMAC"],\
            ERR_CODE=pkg_info["ERR_CODE"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["CERT_REQ"]:
            # pkg_info["PKG_DESC"] = "CERT_REQ"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=pkg_info["HMAC"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["CERT_RPY"]:
            # pkg_info["PKG_DESC"] = "CERT_RPY"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["CERT"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=pkg_info["HMAC"],\
            CERT=pkg_info["CERT"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["CERT_ERR"]:
            # pkg_info["PKG_DESC"] = "CERT_ERR"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=pkg_info["HMAC"],\
            ERR_CODE=pkg_info["ERR_CODE"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["KEY_REQ"]:
            # pkg_info["PKG_DESC"] = "KEY_REQ"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["KEY_INFO"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=pkg_info["HMAC"],\
            KEY_INFO=pkg_info["KEY_INFO"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["KEY_RPY"]:
            # pkg_info["PKG_DESC"] = "KEY_RPY"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["KEY_INFO"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=pkg_info["HMAC"],\
            KEY_INFO=pkg_info["KEY_INFO"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["KEY_ERR"]:
            # pkg_info["PKG_DESC"] = "KEY_ERR"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=pkg_info["HMAC"],\
            ERR_CODE=pkg_info["ERR_CODE"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["COM_MSG"]:
            # pkg_info["PKG_DESC"] = "COM_MSG"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["PAYLOAD"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=pkg_info["HMAC"],\
            PAYLOAD=pkg_info["PAYLOAD"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["COM_ERR"]:
            # pkg_info["PKG_DESC"] = "COM_ERR"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=pkg_info["HMAC"],\
            ERR_CODE=pkg_info["ERR_CODE"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DISCON_REQ"]:
            # pkg_info["PKG_DESC"] = "DISCON_REQ"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=pkg_info["HMAC"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DISCON_CLG"]:
            # pkg_info["PKG_DESC"] = "DISCON_CLG"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["CHALLG"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=pkg_info["HMAC"],\
            CHALLG=pkg_info["CHALLG"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DISCON_RPY"]:
            # pkg_info["PKG_DESC"] = "DISCON_RPY"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["CHALLG_RPY"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=pkg_info["HMAC"],\
            CHALLG_RPY=pkg_info["CHALLG_RPY"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DISCON_ERR"]:
            # pkg_info["PKG_DESC"] = "DISCON_ERR"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=pkg_info["HMAC"],\
            ERR_CODE=pkg_info["ERR_CODE"]\
            )
        else: # package type not support
            raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])


        return msg

    """
    pkg_interp()
    ==============================================
    A function to turn received one received message to a dictionary of parameters

    inputs:
        pkg_msg: a STRING of length at most Constants.MSG_MAX_LENGTH

    outputs:
        pkg_info: a dictionary
    """
    def pkg_interp(self, pkg_msg):
        pkg_info = self.pkg_info_init_gen()

        # check pkg type
        pkg_msg_list = pkg_msg.split(Constants.DELIMITER)
        PKG_TYPE_ID_str = pkg_msg_list[0]
        if re.compile('(\d){1,3}').match(PKG_TYPE_ID_str):
            PKG_TYPE_ID = int(PKG_TYPE_ID_str)
        else:
            raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])

        # check nonce
        pkg_info["NONCE"] = pkg_msg_list[1]
        if not self.nonce_check(pkg_info["NONCE"]):
            raise ValueError(Constants.ERROR_CODE_DICT["EXPIRED_PKG"])

        pkg_info["PKG_TYPE_ID"] = PKG_TYPE_ID
        if PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["HELLO_MSG"]:
            pkg_info["PKG_DESC"] = "HELLO_MSG"
            pkg_info["SRC_ID"] = pkg_msg_list[2]
            pkg_info["PUBLIC_KEY"] = pkg_msg_list[3]
            pkg_info["NEGO_PARAMS"] = Constants.DELIMITER.join(pkg_msg_list[4:])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["ACK_CERT"]:
            pkg_info["PKG_DESC"] = "ACK_CERT"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["DST_ID"] = pkg_msg_list[3]
            pkg_info["PUBLIC_KEY"] = pkg_msg_list[4]
            pkg_info["CERT"] = Constants.DELIMITER.join(pkg_msg_list[5:])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DNY_MSG"]:
            pkg_info["PKG_DESC"] = "DNY_MSG"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[3:])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["CERT_REQ"]:
            pkg_info["PKG_DESC"] = "CERT_REQ"
            pkg_info["HMAC"] = pkg_msg_list[2]
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["CERT_RPY"]:
            pkg_info["PKG_DESC"] = "CERT_RPY"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["CERT"] = Constants.DELIMITER.join(pkg_msg_list[3:])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["CERT_ERR"]:
            pkg_info["PKG_DESC"] = "CERT_ERR"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[3:])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["KEY_REQ"]:
            pkg_info["PKG_DESC"] = "KEY_REQ"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["KEY_INFO"] = Constants.DELIMITER.join(pkg_msg_list[3:])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["KEY_RPY"]:
            pkg_info["PKG_DESC"] = "KEY_RPY"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["KEY_INFO"] = Constants.DELIMITER.join(pkg_msg_list[3:])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["KEY_ERR"]:
            pkg_info["PKG_DESC"] = "KEY_ERR"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[3:])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["COM_MSG"]:
            pkg_info["PKG_DESC"] = "COM_MSG"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["PAYLOAD"] = Constants.DELIMITER.join(pkg_msg_list[3:])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["COM_ERR"]:
            pkg_info["PKG_DESC"] = "COM_ERR"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[3:])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DISCON_REQ"]:
            pkg_info["PKG_DESC"] = "DISCON_REQ"
            pkg_info["HMAC"] = pkg_msg_list[2]
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DISCON_CLG"]:
            pkg_info["PKG_DESC"] = "DISCON_CLG"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["CHALLG"] = Constants.DELIMITER.join(pkg_msg_list[3:])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DISCON_RPY"]:
            pkg_info["PKG_DESC"] = "DISCON_RPY"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["CHALLG_RPY"] = Constants.DELIMITER.join(pkg_msg_list[3:])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DISCON_ERR"]:
            pkg_info["PKG_DESC"] = "DISCON_ERR"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[3:])
        else: # package type not support
            # reply error code to the sender
            raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])

        # need to add HMAC check

        return pkg_info

    """
    pkg_info_init_gen()
    ==============================================
    A function to generate a pkg_info dictionary.

    outputs:
        pkg_info: the dictionary
    """
    def pkg_info_init_gen(self):
        return {key:None for key in Constants.PKG_INFO_ITEMS}

    """
    nonce_gen()
    ===========
    outputs:
        nonce: follow the structure in Constants
    """
    def nonce_gen(self):
        nonce = str(time.time())
        return nonce

    """
    nonce_check()
    ==============
    check whether the nonce is valid

    inputs:
        nonce
        rules: dictionary of rules, say t_wind

    output:
        Rst: True/False
        ErrorCode: None or ErrorCode
    """
    def nonce_check(self, nonce):
        now = time.time()
        if now - float(nonce) > Constants.PKG_TOL:
            return False, Constants.ERROR_CODE_DICT("EXPIRED_PKG")
        else:
            return True, None

    def gen_pub_prv_keys(self):
        pass

    """
    respond_state_machine()
    =======================
    React based on the received pkg and current status.

    inputs:
        pkg_rev: received package (string)

    output:
        pkg_send: package to send
    """
    def respond_state_machine(self, pkg_rev):
        pkg_info = self.pkg_interp(pkg_rev)
        try:
            if pkg_info["PKG_TYPE_ID"] is None:
                raise Exception(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["HELLO_MSG"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["ACK_CERT"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["DNY_MSG"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["CERT_REQ"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["CERT_RPY"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["CERT_ERR"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["KEY_REQ"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["KEY_RPY"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["KEY_ERR"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["COM_MSG"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["COM_ERR"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["DISCON_REQ"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["DISCON_CLG"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["DISCON_RPY"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["DISCON_ERR"]:
                pass
        except Exception as e:
            raise

    """
    cert_update()
    =====================
    Generate/update the certification.
    Certification is generated using
    {USER_ID}|{cert generation time}|{signed hash value of previous two parts}

    Certification will be updated if 1) expired 2) doesn't exist
    """
    def cert_update(self):
        def cert_gen():
            cur_time = str(time.time())

            message = str(self.user_id) + '|' + cur_time
            msg_hash = SHA1().hash(message.encode())[-8:]
            sign = self.sign_obj.sign(int(msg_hash, 16))
            self.cert = message + '|' + str(sign)
        if self.cert is None:
            cert_gen()
            return
        cert_gen_time = float(self.cert.split('|')[1])
        if (time.time() - cert_gen_time) > Constants.CERT_TOL/2:
            cert_gen()
            return

    def cert_check(self, cert, SRC_ID, N, e):
        cert_check_obj = RSA(e=e, N=N)
        cert_parts = self.cert.split('|')
        if len(cert_parts) == 3:
            try:
                cert_SRC_ID = int(cert_parts[0])
                cert_gen_time = float(cert_parts[1])
                cert_sign = int(cert_parts[2])
            except Exception as e:
                return False

            if cert_SRC_ID != SRC_ID: # user not match
                return False
            if (time.time() - cert_gen_time) > Constants.CERT_TOL: # expire
                return False

            message = cert_parts[0] + '|' + cert_parts[1]
            msg_hash = SHA1().hash(message.encode())[-8:]
            return cert_check_obj.check_sign(cert_sign, int(msg_hash, 16))
        else:
            return False
