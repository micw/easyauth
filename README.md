# EasyAuth provides common authentication endpoints for common authentication backends

## Configuration

The configuration can be done via spring boot's configuration methods, including `yaml` files and environment variables. Every
property in the yaml examples can also be set by the environment variable with the same name.

## UserProvider backends

The backend for providing users is defined via the `userProvider` property. The property value can either one of the
predefined providers or a full qualified name of a class which implements `IUserProvider`.

### LDAP backend

The backend assumes that there are LDAP objects which represents users and LDAP objects which represents groups. Groups must reference users.

Example configuration:

```
userProvider: ldap

ldap:
  serverUrl: ldaps://ldap.example.com
  baseDn: dc=example,dc=com
  
  bindDn: cn=ldapuser,dc=example,dc=com
  bindPassword: s3cr3t!
  
  usersFilter: (&(|({usernameAttribute}={username})({emailAttribute}={username}))(objectClass=person))
  additionalUsersDn: ou=Users

  displayNameAttribute: displayName
  usernameAttribute: uid
  emailAttribute: mail
  
  groupsFilter: (uniqueMember={userDn})
  additionalGroupsDn: ou=Groups
  groupNameAttribute: cn
```

LDAP configuration properties:

* `serverUrl` (required) - The URL of the LDAP server. Both, ldap:// and ldaps:// are supported
* `baseDn` (required) - The base DN for all LDAP searches
* `bindDn`, `bindPassword` (required) - An LDAP account that is allowed to query for users and search for groups
* `usersFilter` (see below) - The filter to query for users
* `groupFilter` (see below) - The filter to search for groups
* `additionalUsersDn` (optional) - An optional suffix for the baseDn on which users are searched
* `additionalGroupDn` (optional) - An optional suffix for the baseDn on which groups are searched
* `displayNameAttribute` (required, default "displayName") The attribute of the user object that holds the display name
* `usernameAttribute` (required, default "uid") The attribute of the user object that holds the user name
* `emailAttribute` (required, default "mail") The attribute of the user object that holds the email
* `groupNameAttribute` (required, default "cn") The attribute of the group object that holds the group name

The usersFilter:

* This filter is used to find a user by it's username
* Default value: `(&(|({usernameAttribute}={username})({emailAttribute}={username}))(objectClass=person))`
* Allowed placeholders:
    * `{usernameAttribute}` - replaced with `usernameAttribute` from config
    * `{emailAttribute}` - replaced with `emailAttribute` from config
    * `{username}` - replaced with the username that tries to authenticate

The groupFilter:

* This filter is used to find a user's groups
* Default value: `(uniqueMember={userDn})`
* Allowed placeholders:
    * `{userDn}` - replaced with Dn of the user object
    * `{username}` - replaced with the username of the user object

### Static user backend

The backend authenticates against a static list of users

Example configuration:

```
userProvider: static

static:
  users: |
    admin:Administrator:admin@example.com:{plain}password:group1,group2,group3
    user:User:user@example.com:{plain}password:group3
```

The only configuration property is static.users which contains user separated by whitespace or newlines.
The fields of a user are separates by colons and contains (in this order):

* username
* displayName
* email
* password hash
* comma-separated list of groups (optional)

The password hash contains of the scheme followed by the hashed password. The following schemes are supported:

* `{plain}` - plaintext password, for testing purposes only
* `{bcrypt}` - bcrypt encoded password hash

## Authentication endpoints

### Basic authentication

The endpoint for basic authentication is `/auth/basic`. It can be used as 
[auth backend for nginx](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/), [kubernetes ingress](https://kubernetes.github.io/ingress-nginx/examples/auth/external-auth/) and others.

By default, all authenticated users are allowed. Groups can be restricted by query parameters.

The following query parameters are honored:

* `allowGroups` - comma separated list of group names. The user has to be in _one_ of these groups.
* `requireGroups` - comma separated list of group names. The user has to be in _all_ of these groups.
* `realmName` - the basic auth realm name which is displayed by most browsers when prompting for username and password
