import os
import pwd
import ldap3
from ldapauthenticator.ldapauthenticator import LDAPAuthenticator
from tornado import gen
from traitlets import List
from traitlets import Unicode
from traitlets import Set

class LDAP2LocalUserAuthenticator(LDAPAuthenticator):

    local_useradd_template = Unicode(
        config=True,
        help="Template to create local user accounts e.g. 'useradd -m -d /home/{{uid}} -s /bin/bash {{uid}} -c \"{{sn}} - {{givenName}} - {{mail}} - /{datetime.datetime.now():%Y-%m}/{{ou}}\""
    )

    local_users = Set(
        config=True,
        help="List of additional local user accounts e.g. not in LDAP"
    )

    @gen.coroutine
    def authenticate(self, handler, data):        
        username = data['username']
        password = data['password']

        if username in self.local_users:
            import crypt # Interface to crypt(3), to encrypt passwords.
            import spwd # Shadow password database (to read /etc/shadow)
            # Try, if one of local_users
            try:
                enc_pwd = spwd.getspnam(username)[1]
                if enc_pwd in ["NP", "!", "", None]:
                    self.log.warning(f"user {username} has no password set")
                    return None
                if enc_pwd in ["LK", "*"]:
                    self.log.error(f"account {username} is locked")
                    return None
                if enc_pwd == "!!":
                    self.log.error(f"password for {username} has expired")
                # Encryption happens here, the hash is stripped from the
                # enc_pwd and the algorithm id and salt are used to encrypt
                # the password.
                if crypt.crypt(password, enc_pwd) == enc_pwd:
                    return username
                else:
                    self.log.warning(f"incorrect password for {username}")
                    return None
            except KeyError:
                self.log.error(f"user {username} not found")
                return None

        # ask for LDAP Authentication
        result = super().authenticate(handler,data)
        self.log.debug(f'Login of LDAPUser {self.user_attribute}={username} ok ({result.result()})')

        # c.LDAP2LocalUserAuthenticator.auth_state_attributes must include LDAP attributes to use it in useradd_cmd
        if isinstance(result.result(), dict):
            attr = result.result()['auth_state']
            self.log.debug(f'LDAPUser {self.user_attribute}={username} attributes ({attr})')
        else:
            raise ValueError(f"Jupyterhub LDAPAuthenticator configuration variable 'auth_state_attributes' must be set")

        if result.result() and self.local_useradd_template:
            try:
                user = pwd.getpwnam(username)
            except KeyError:
                useradd_cmd = self.local_useradd_template.format(**attr)
                os.system(useradd_cmd)
                self.log.info(f'User {self.user_attribute}={username} added as local user ({useradd_cmd})')

        return result


if __name__ == "__main__":
    import getpass
    import datetime
    c = LDAP2LocalUserAuthenticator()
    c.server_address = "ldap.organisation.org"
    c.server_port = 636
    c.use_ssl = True
    c.bind_dn_template = "uid={username},ou=people,dc=organisation,dc=org"
    c.user_attribute = "uid"
    c.user_search_base = "ou=people,dc=organisation,dc=org"
    c.attributes = ["uid", "cn", "mail", "ou", "o"]
    # The following is an example of a search_filter which is build on LDAP AND and OR operations
    # here in this example as a combination of the LDAP attributes 'ou', 'mail' and 'uid'
    sf = "(&(o={o})(ou={ou}))".format(o="yourOrganisation", ou="yourOrganisationalUnit")
    sf += "(&(o={o})(mail={mail}))".format(o="yourOrganisation", mail="yourMailAddress")
    c.search_filter = "(&({{userattr}}={{username}})(|{}))".format(sf)
    c.auth_state_attributes = c.attributes
    c.local_users = {}
    # Beware of this template - it should be tested carefully
    c.local_useradd_template = f"useradd -m -d /home/{{uid}} -s /bin/bash {{uid}} -c \"{{cn}} - {{mail}} - {datetime.datetime.now():%Y-%m}/{{o}}/{{ou}}/\"\n"
    username = input("Username: ")
    passwd = getpass.getpass()
    data = dict(username=username, password=passwd)
    rs = c.authenticate(None, data)
    print(rs.result())
