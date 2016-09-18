import ldap
import ldap.modlist as modlist
from secrets import bindDN, bindPW, adHost

LDAP_SERVER = "ldaps://" + adHost + ":636"
BIND_DN = bindDN
BIND_PASS = bindPW

def createUser(username, password, baseDN, name, surename, domain):

  # LDAP connection
  try:
      ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, 0)
      ldapConnection = ldap.initialize(LDAP_SERVER)
      ldapConnection.simple_bind_s(BIND_DN, BIND_PASS)
  except ldap.LDAPError, error_message:
      print "Error connecting to LDAP server: %s" % error_message
      return False

  # Check if user exists
  try:
      userResults = ldapConnection.search_s(baseDN, ldap.SCOPE_SUBTREE,
                                              '(&(sAMAccountName=' +
                                              username +
                                              ')(objectClass=person))',
                                              ['distinguishedName'])
  except ldap.LDAPError, error_message:
      print "Error finding username: %s" % error_message
      return False

  # Check the results
  if len(userResults) != 0:
      print "User", username, "already exists in AD:", \
            userResults[0][1]['distinguishedName'][0]
      return False

  # Build our user
  userDN = 'cn=' + name + ' ' + surename + ',' + baseDN
  userAttrs = {}
  userAttrs['objectClass'] = \
            ['top', 'person', 'organizationalPerson', 'user']
  userAttrs['cn'] = name + ' ' + surename
  userAttrs['userPrincipalName'] = username + '@' + domain
  userAttrs['sAMAccountName'] = username
  userAttrs['givenName'] = name
  userAttrs['sn'] = surename
  userAttrs['displayName'] = name + ' ' + surename
  # User will be disabled
  userAttrs['userAccountControl'] = '514'
  userAttrs['mail'] = username + '@' + domain
  userAttrs['pwdLastSet'] = '-1'
  #userAttrs['homeDirectory'] = '/home/users/' + username
  userLDIF = modlist.addModlist(user_attrs)

  # Prepare the password
  unicodePass = unicode('\"' + password + '\"', 'iso-8859-1')
  passwordValue = unicodePass.encode('utf-16-le')
  addPass = [(ldap.MOD_REPLACE, 'unicodePwd', [passwordValue])]

  # 512 will set user account to enabled
  modAcct = [(ldap.MOD_REPLACE, 'userAccountControl', '512')]

  # Add the new user account
  try:
      ldapConnection.add_s(userDN, userLDIF)
  except ldap.LDAPError, error_message:
      print "Error adding new user: %s" % error_message
      return False

  # Add the password
  try:
      ldapConnection.modify_s(userDN, addPass)
  except ldap.LDAPError, error_message:
      print "Error setting password: %s" % error_message
      return False

  # Enable the user account
  try:
      ldapConnection.modify_s(userDN, modAcct)
  except ldap.LDAPError, error_message:
      print "Error enabling user: %s" % error_message
      return False

  # LDAP unbind
  ldapConnection.unbind_s()

  # All is good
  return True

username = "xxx"
password = "ComplicatedPassword1!"
baseDN = "BASE_DN"
name = "Jan"
surename = "Kowalski"
domain = "domain.com"

createUser(username, password, baseDN, name, surename, domain)
