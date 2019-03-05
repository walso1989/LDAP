# Script description: Connects to AD using SSL LDAPv3 and performs the password reset of a user and unlocks his/hers corresponding account

import logging
import random
import string

import ldap

"""
def ad_find_user_cn():
    ########## performing a simple ldap query ####################################

    ldap_base = "dc=example,dc=com"
    query = "(uid=maarten)"
    result = con.search_s(ldap_base, ldap.SCOPE_SUBTREE, query)
"""


def ad_password_chage(ad_connection_username, ad_connection_password, username, new_password, domain):
    ad_user = username + "@" + domain

    logger.info("Changing password for user " + ad_user)

    logger.info("Connecting to AD")
    try:
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        ad = ldap.initialize("LDAPS://DOMAIN.COM")
        ad.set_option(ldap.OPT_REFERRALS, 0)
        ad.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        ad.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
        ad.set_option(ldap.OPT_X_TLS_DEMAND, True)
        ad.set_option(ldap.OPT_DEBUG_LEVEL, 255)
        ad.simple_bind_s(ad_connection_username, ad_connection_password)

        # Reset Password
        logger.info("Reseeting user " + ad_user + " password")
        unicode_pass = unicode('\"' + str(new_password) + '\"', 'iso-8859-1')
        password_value = unicode_pass.encode('utf-16-le')
        add_pass = [(ldap.MOD_REPLACE, 'unicodePwd', [password_value])]

        ad.modify_s(username, add_pass)
        logger.info("Password reset for user " + ad_user + " completed")

        # Its nice to the server to disconnect and free resources when done
        logger.info("Closing connection to AD")
        ad.unbind_s()

    except Exception as strerror:
        logger.info("Error reseting password: " + strerror)


def main():
    # Values to be use to connect to AD

    domain = "142.100.64.11"
    ad_connection_username = "cn=admin,dc=example,dc=com"
    ad_connection_password = "Aut0Mat3_2019"
    logger.info("Reading connection parameters: AD IP " + domain + " AD User: " + ad_connection_username)

    new_password = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(8)])
    username = "wsolano@" + domain

    logger.info("Calling function to change AD password")
    ad_password_chage(ad_connection_username, ad_connection_password, username, new_password, domain)


if __name__ == "__main__":
    # Creating and setting logger
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    handler = logging.FileHandler("process.log")
    handler.setLevel(logging.INFO)

    # Create a logging format
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)

    # Add the handlers to the logger
    logger.addHandler(handler)

    main()
