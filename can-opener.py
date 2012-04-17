#!/usr/bin/python
#
# (c) Codento Oy, Helsinki Finland, 2012
# Authors: Santeri Paavolainen, <santeri.paavolainen@codento.com>
#
# Tool to manage EC2 security group automatically and *STATEFULLY*,
# granting accesses to given (or automatically determined) ip
# addresses.
#
# This tool can be run either to add/remove entries in a security
# group, to list them, or to manage them. Note that security group
# accesses, e.g. firewall holes are managed in a "stateful"
# manner. Since EC2 SGs do not allow any other state such as tags,
# external data etc. this tool uses SimpleDB to store "state"
# information about firewall holes.
#
# Well, the only really useful information is when the hole was
# opened.
#
# The port opening time is used with the --action=manage (together
# with --lifetime and --mode options) to potentially remove entries
# from a security group.
#
# In practice this can be used by developers to automatically open
# "holes" in a firewall with regards to their current public IP
# address. These holes can then be also automatically "removed" when
# their validity lifetime is exceeded.

from boto.exception import SDBResponseError, BotoServerError
import boto.ec2
import boto.sdb
from boto.iam.connection import IAMConnection
import getopt
import sys
import os
import urllib
import time
import hashlib
import logging
import boto.s3.connection

class StatefulSecurityGroup(object):
    def __init__(self, sg, sdb):
        self.sg = sg
        self.sdb = sdb
        self.log = logging.getLogger(__name__)

    @property
    def name(self):
        return self.sg.name

    def __grant_key(self, cidr, proto, from_port, to_port):
        return hashlib.sha1("%s,%s,%s,%s,%s" % (str(self.sg.name), str(cidr), str(proto), str(from_port), str(to_port))).hexdigest()

    def __get_grant(self, cidr, proto, from_port, to_port):
        key = self.__grant_key(cidr, proto, from_port, to_port)
        item = self.sdb.get_item(key)
        if not item:
            self.log.debug("New item for key %r", key)
            item = self.sdb.new_item(key)
            item['sg'] = self.sg.name
            item['cidr'] = cidr
            item['proto'] = proto
            item['from_port'] = str(from_port)
            item['to_port'] = str(to_port)
        return item

    def __del_grant(self, cidr, proto, from_port, to_port):
        key = self.__grant_key(cidr, proto, from_port, to_port)
        item = self.sdb.get_item(key)
        if item:
            self.log.debug("Deleting key %r", key)
            item.delete()

    def add_grant(self, cidr, proto, from_port, to_port):
        self.log.info("Adding grant %s -> %s:%d-%d", cidr, proto, from_port, to_port)
        self.sg.authorize(proto, str(from_port), str(to_port), cidr)
        item = self.__get_grant(cidr, proto, from_port, to_port)
        item.add_value('added', int(time.time()))
        item.save()

    def has_grant(self, cidr, proto, from_port, to_port):
        # go through all rules and their individual grants
        for rule in self.sg.rules:
            self.log.debug("has_grant: (%r,%r,%r,%r) <=> (%r,%r,%r,%r)",
                           cidr, proto, from_port, to_port,
                           [ grant.cidr_ip for grant in rule.grants ],
                           rule.ip_protocol, rule.from_port, rule.to_port)

            if (rule.ip_protocol == proto
                and int(rule.from_port) == from_port
                and int(rule.to_port) == to_port
                and cidr in [ grant.cidr_ip for grant in rule.grants ]):

                self.log.debug("has_grant: matched")
                return True

        self.log.debug("has_grant: no match found")
        return False

    def update_grant(self, cidr, proto, from_port, to_port):
        self.log.info("Updating grant %s -> %s:%d-%d", cidr, proto, from_port, to_port)
        item = self.__get_grant(cidr, proto, from_port, to_port)
        item.add_value('added', int(time.time()))
        item.save()

    def del_grant(self, cidr, proto, from_port, to_port):
        #print "del_grant: cidr=%r, proto=%r, from_port=%r, to_port=%r" % (cidr, proto, from_port, to_port)
        self.log.info("Deleting grant %s -> %s:%d-%d", cidr, proto, from_port, to_port)
        self.sg.revoke(proto, str(from_port), str(to_port), cidr)
        self.__del_grant(cidr, proto, from_port, to_port)

    def get_grants(self):
        # return list of
        # (cidr,low,high,proto,lowest_added,highest_added,is_active)
        # values, note that *_added can be None if this grant doesn't
        # have a matching simpledb record

        # This is trickiest of them all, because we want to return
        # union of both SG rules, and those that exist in
        # simpledb. Merging is handled like this:
        #
        # 1) If (cidr,proto,low,high) exist in both, then add full
        #    record. *_added values are computed, is_active is True.
        #
        # 2) If only in SG, add with *_added as None, is_active as
        #    True.
        #
        # 3) If not in SG, but in SDB, *_added are computed but
        #    is_active is False.

        rules = {}

        for rule in self.sg.rules:
            self.log.debug("Sg %s rule: %r", self.sg.name, rule)

            for cidr in [ grant.cidr_ip for grant in rule.grants ]:
                key = self.__grant_key(cidr, rule.ip_protocol, rule.from_port, rule.to_port)
                rules[key] = [cidr, rule.ip_protocol, int(rule.from_port), int(rule.to_port), None, None, True]

        # print "rules now: %r" % (rules,)

        for item in self.sdb.select('select * from `%s` where `sg` = "%s"' % (self.sdb.name, self.sg.name)):
            self.log.debug("Sdb %s sg %s item: %r", self.sdb.name, self.sg.name, item)
            (cidr, proto, from_port, to_port) = (item['cidr'], item['proto'], int(item['from_port']), int(item['to_port']))

            # If there are any invalid entries, remove them
            # indiscriminantly. At least if we can.
            if self.__grant_key(cidr, proto, from_port, to_port) != item.name:
                self.sdb.remove_item(item.name)
                print "%r did not match generated grant key, removed" % (item.name)
                continue

            def added_as_list():
                if type(item['added']) == list:
                    return item['added']
                return [item['added']]

            lowest_added = min([ int(added) for added in added_as_list() ])
            highest_added = max([ int(added) for added in added_as_list() ])
            key = item.name

            if key in rules:
                self.log.debug("Matching firewall rule found")
                rules[key][4:6] = [lowest_added, highest_added]
            else:
                self.log.debug("No matching firewall rule found")
                rules[key] = [ cidr, proto, from_port, to_port, lowest_added, highest_added, False]

        self.log.debug("Final rules: %r", rules.values())
        return rules.values()

STRICT = 1
NORMAL = 2
LAX    = 3

def usage():
    print """Usage: %s [-h|--help] [OPTIONS] [IP ...]

Valid OPTIONS are:

  -A, --access-key ACCESS-KEY
  -S, --secret-key SECRET-KEY
  -R, --region REGION

  -s, --security-group SECURITY-GROUP
  -d, --domain SIMPLEDB-DOMAIN

  -a, --action add|remove|list|manage
  or: --add|--remove|--list|--manage
  -m, --mode strict|normal|lax
  -l, --lifetime SECS

  -p, --ports [tcp:|udp:]PORT[-PORT]|all|*

IP can be simple ip address or CIDR block. If no IP address
is given and one is needed, then current Internet-visible
external IP address is fetched using http://api.externalip.net/ip/.

ACCESS-KEY, SECRET-KEY and REGION can be all specified via
environmental variables AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
and AWS_REGION respectively.
""" % (sys.argv[0])

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hA:S:R:s:a:l:m:d:p:nd:",
                                   ["help", "access-key=", "secret-key=", "region=", "security-groups=", "domain=", "ports=",
                                    "domain=", "action=", "mode=", "lifetime=", "dry-run",
                                    "add", "remove", "list", "manage", "initialize", "initialize-destructive", "log="])
    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit(2)

    access_key = None # boto defaults to AWS_ACCESS_KEY_ID in env
    secret_key = None # boto defaults to AWS_SECRET_ACCESS_KEY in env
    region = os.getenv("AWS_REGION", "us-east-1") # this would be nice addition to boto
    security_groups = "can-opener-sg"
    domain_name = "can-opener-sdb"
    ips = []
    ports = '22,8080'
    action = 'add'
    mode = STRICT
    lifetime = 8 * 60 * 60
    dry_run = False
    log_level = logging.WARNING

    # TODO: Fetch all of this information, e.g. ports, addesses
    # etc. from config file, hopefully also allowing different ports
    # to be specified for different SGs. This would allow this tool to
    # be used to "automatically" open all needed ports for a developer
    # for various different projects. (Also, have "active = no"
    # possible to specify for some things.)

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit(0)
        elif o in ("-A", "--access-key"):
            access_key = a
        elif o in ("-S", "--secret-key"):
            secret_key = a
        elif o in ("-R", "--region"):
            region = a
        elif o in ("-s", "--security-groups"):
            security_groups = a
        elif o in ("-p", "--ports"):
            ports = a
        elif o in ('-a', '--action'):
            action = a
        elif o in ('-l', '--lifetime'):
            lifetime = int(a)
        elif o in ('-m', '--mode'):
            mode = { 'strict': STRICT, 'normal': NORMAL, 'lax': LAX }[a]
        elif o in ('-n', '--dry-run'):
            dry_run = True
        elif o in ('--add',):
            action = 'add'
        elif o in ('--remove',):
            action = 'remove'
        elif o in ('--list',):
            action = 'list'
        elif o in ('--manage',):
            action = 'manage'
        elif o in ('--initialize',):
            action = 'initialize'
        elif o in ('--initialize-destructive',):
            action = 'initialize-destructive'
        elif o in ('--log',):
            log_level = getattr(logging, a.upper())
        elif o in ('-d', '--domain'):
            domain_name = a
        else:
            assert False, "unhandled option"

    logging.basicConfig(level=log_level)

    def get_ips():
        if len(args) == 0:
            u = urllib.urlopen('http://api.externalip.net/ip/')
            ip = u.read()
            ips = [ ip ]
        else:
            ips = args

        ips = map(lambda ip: '%s/32' % ip if not '/' in ip else ip, ips)
        get_ips = lambda: ips
        return ips

    def get_ports():
        ret = []
        for p in ports.split(","):
            if ':' in p:
                (proto, port) = p.split(":")
                p = port
            else:
                proto = 'tcp'

            if p == 'all' or p == '*':
                (low, high) = (0, 65535)
            elif '-' in p:
                (low, high) = p.split('-')
            else:
                (low, high) = (p, p)

            # TODO: do protocol name mapping, e.g. "http" => 80
            low = int(low)
            high = int(high)

            ret.append((proto, low, high))

        return ret

    def get_sg_names():
        return security_groups.split(',')

    def check_remove_grant(mode, ports, lifetime, cidr, proto, from_port, to_port, first_added, last_added, is_active):
        if not is_active:
            # Under no circumstance we want to keep non-active
            # (e.g. things only in simpledb without real match in
            # active grants)
            return "OnlyInDb"
        elif first_added is None or last_added is None:
            # Unstateful holes are allowed only under lax mode,
            # otherwise they're removed.
            if mode != LAX:
                return "NotIndb"
        elif last_added + lifetime < time.time():
            # Lifetime exceeded?
            return "TooOld"
        elif mode == STRICT:
            # In strict mode we require that grants honor the
            # given port ranges *exactly*.
            good_grant = False
            for (p, low, high) in ports:
                if p == proto and from_port == low and to_port == high:
                    good_grant = True
                    break

            if not good_grant:
                return "BadRange"

        return None

    conn = boto.ec2.connect_to_region(region, aws_access_key_id=access_key, aws_secret_access_key=secret_key)
    sdb = boto.sdb.connect_to_region(region, aws_access_key_id=access_key, aws_secret_access_key=secret_key)

    for sg_name in get_sg_names():
        if action == 'initialize' or action == 'initialize-destructive':
            destructive = action == 'initialize-destructive'
            iam = IAMConnection(aws_access_key_id=access_key, aws_secret_access_key=secret_key)

            owner_id = None

            sg_exists = False

            for sg in conn.get_all_security_groups():
                if sg.owner_id:
                    ownerid = sg.owner_id
                if sg.name == sg_name:
                    sg_exists = True

            assert ownerid is not None
            group_name = 'can-opener-grp'
            user_name = 'can-opener-user'
            policy_name = 'can-opener-policy'
            policy_json = """{
  "Statement": [
    {
      "Sid": "CanOpenerEC2Allow",
      "Action": [
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:RevokeSecurityGroupIngress"
      ],
      "Effect": "Allow",
      "Resource": "*"
    },
    {
      "Sid": "CanOpenerSDBAllow",
      "Action": [
        "sdb:DeleteAttributes",
        "sdb:GetAttributes",
        "sdb:PutAttributes",
        "sdb:Select"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:sdb:%(region)s:%(ownerid)s:domain/%(domain)s"
    }
  ]
}""" % { 'region': region,
        'ownerid': ownerid,
        'domain': domain_name }

            #print "policy_json = %s" % (policy_json,)

            # 1) Check if IAM group 'can-opener-grp' exists, if not,
            # create and set policy rules.
            group_exists = group_name in [g.group_name for g in iam.get_all_groups().list_groups_response.list_groups_result.groups]
            if group_exists and destructive:
                print "DESTROY: Destroying old group %s" % (group_name,)
                for user in iam.get_group(group_name).get_group_response.get_group_result.users:
                    print "DESTROY: Removing user %s from group %s" % (user.user_name, group_name)
                    iam.remove_user_from_group(group_name, user.user_name)
                for policy in iam.get_all_group_policies(group_name).list_group_policies_response.list_group_policies_result.policy_names:
                    print "DESTROY: Removing policy %s from group %s" % (policy, group_name)
                    iam.delete_group_policy(group_name, policy)
                iam.delete_group(group_name)
            if not group_exists or destructive:
                print "INITIALIZE: Group %s does not exist, creating" % (group_name,)
                group = iam.create_group(group_name)
                print "INITIALIZE: Adding policy %s to group %s" % (policy_name, group_name)
                iam.put_group_policy(group_name, policy_name, policy_json)

            # 2) Check if IAM user 'can-opener-user' exists, if not,
            # create, set to group 'can-opener-grp', get credentials
            # and print them out.
            user_exists = user_name in [u.user_name for u in iam.get_all_users().list_users_response.list_users_result.users]
            if user_exists and destructive:
                for key in iam.get_all_access_keys(user_name).list_access_keys_response.list_access_keys_result.access_key_metadata:
                    print "DESTROY: Destroying access key %s of user %s" % (key.access_key_id, user_name)
                    iam.delete_access_key(key.access_key_id, user_name)
                print "DESTROY: Destructing old user %s" % (user_name,)
                iam.delete_user(user_name)
            if not user_exists or destructive:
                print "INIITALIZE: User %s does not exist, creating" % (user_name,)
                user = iam.create_user(user_name)
                print "INITIALIZE: Adding user %s to group %s" % (user_name, group_name)
                iam.add_user_to_group(group_name, user_name)
                print "INITIALIZE: Creating new access key for user %s" % (user_name,)
                key = iam.create_access_key(user_name).create_access_key_response.create_access_key_result.access_key
                access_key = key.access_key_id
                secret_key = key.secret_access_key

                print """
****************************************************************************
IMPORTANT! The secret key cannot be recovered later - make a note of it NOW!

    User:           %(userid)s
    Access Key:     %(accesskey)s
    Secret Key:     %(secretkey)s

    Export:         export AWS_ACCESS_KEY_ID=%(accesskey)s AWS_SECRET_ACCESS_KEY=%(secretkey)s
****************************************************************************
""" % {
                    'userid': user_name,
                    'accesskey': access_key,
                    'secretkey': secret_key }

            # 3) Check if SimpleDB domain exist, if not, create.
            try:
                domain = sdb.get_domain(domain_name, True)
                print "INITIALIZE: Domain %s already exists, not touching it" % (domain_name,)
            except SDBResponseError, err:
                if err.error_code != 'NoSuchDomain':
                    raise err
                print "INITIALIZE: Domain %s does not exist, creating it" % (domain_name,)
                domain = sdb.create_domain(domain_name)

            # 4) Check if security group exist, if not, create.
            if sg_exists:
                print "INITIALIZE: Security group %s already exists, not touching it" % (sg_name,)
            else:
                print "INITIALIZE: Security group %s does not exist, creating it" % (sg_name,)
                conn.create_security_group(sg_name, 'Created by Can Opener')

            # Done! Skip to next.
            continue

        try:
            domain = sdb.get_domain(domain_name, True)
        except SDBResponseError, err:
            if err.error_code != 'NoSuchDomain':
                raise err
            domain = sdb.create_domain(domain_name)

        sg = conn.get_all_security_groups([sg_name])[0]
        s = StatefulSecurityGroup(sg, domain)

        if action == 'add':
            ips = get_ips()
            valid_ports = get_ports()

            for ip in ips:
                for (proto, low, high) in valid_ports:
                    if s.has_grant(ip, proto, low, high):
                        print "UPDATE: %s: %s -> %s:%d-%d" % (s.name, ip, proto, low, high)
                        if not dry_run:
                            s.update_grant(ip, proto, low, high)
                    else:
                        print "ADD: %s: %s -> %s:%d-%d" % (s.name, ip, proto, low, high)
                        if not dry_run:
                            s.add_grant(ip, proto, low, high)
        elif action == 'remove':
            ips = get_ips()
            valid_ports = get_ports()

            for ip in ips:
                for (proto, low, high) in valid_ports:
                    if s.has_grant(ip, proto, low, high):
                        print "REMOVE: %s: %s -> %s:%d-%d" % (s.name, ip, proto, low, high)
                        if not dry_run:
                            s.del_grant(ip, proto, low, high)
        elif action == 'list':
            print "%s %s" % (sg_name, '-' * (76 - len(sg_name)))
            print "%-20s %-15s %-30s %-8s" % ("CIDR", "Proto & Ports", "Time range", "Active")

            for (cidr, proto, from_port, to_port, first_added, last_added, is_active) in s.get_grants():
                proto_and_ports = "%s:%d-%d" % (proto, from_port, to_port)
                if first_added is None or last_added is None:
                    added = "---"
                else:
                    added = "%d-%d" % (first_added, last_added)

                print "%-20s %-15s %-30s %-8s" % (cidr, proto_and_ports, added, is_active)
        elif action == 'manage':
            valid_ports = get_ports()
            for (cidr, proto, from_port, to_port, first_added, last_added, is_active) in s.get_grants():
                reason = check_remove_grant(mode, valid_ports, lifetime,
                                            cidr,
                                            proto, from_port, to_port,
                                            first_added, last_added,
                                            is_active)
                if reason:
                    print "REMOVE: %s: %s -> %s:%d-%d (%s)" % (s.name, cidr, proto, from_port, to_port, reason)
                    if not dry_run:
                        s.del_grant(cidr, proto, from_port, to_port)
        else:
            print "ERROR: Unrecognized action '%s'" % (action,)
            sys.exit(2)

if __name__ == "__main__":
    main()
