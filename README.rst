=============
"Can opener"
=============

*Can opener* is a tool to automatically manage `Amazon Web Services
<http://aws.amazon.com/>`_ network firewall holes. It is meant to be
used by *developers* and potentially also *system administrators*. If
you are neither of those, or do not know basics of AWS services,
please understand that this tool might not be for you.

    **What is it used for?** Imagine the following scenario: Your
    development and test machines are hosted in AWS. You have
    everything set up nice and secure, but you are still iffy about
    making your Jenkins instance world-visible. So you open only those
    addresses and port combinations that are only absolutely required.

    But you or your team are on the road, traveling from city to
    city. To keep ship tight, you need to continuously update firewall
    rules, first to include your current address, then remove that
    when no longer necessary.

    This is a tool that makes that chore go away.

Just tell me how to use it!
---------------------------

Provided you've set up ``AWS_ACCESS_KEY_ID`` and
``AWS_SECRET_ACCESS_KEY`` you can jump in and use it like this (if
not, see below)::

    $ can-opener
    ADD: can-opener-sg: 88.115.164.95/32 -> tcp:22-22
    ADD: can-opener-sg: 88.115.164.95/32 -> tcp:8080-8080

What did it do? It opened access to tcp ports 22 and 8080 in security
group ``can-opener-sg`` to IP address ``88.115.164.95``. This is
obvious. What you didn't see was that can opener **stored
information** about this access to SimpleDB. This information can be
later used to automatically remove accesses that were created "too
long" ago::

    $ can-opener --manage --tags ''
    REMOVE: can-opener-sg: 85.156.38.7/32 -> tcp:22-22 (TooOld)
    REMOVE: can-opener-sg: 77.86.202.212/32 -> tcp:8080-8080 (TooOld)
    REMOVE: can-opener-sg: 85.156.38.7/32 -> tcp:8080-8080 (TooOld)
    REMOVE: can-opener-sg: 77.86.202.212/32 -> tcp:22-22 (TooOld)

So what now happened? Can opener retrieved information from SimpleDB,
compared it against actual firewall rules and determined that accesses
from 85.156.38.7 and 77.86.202.212 were inactive for too long time and
removed them.

You can also list any existing accesses::

    $ can-opener --list
    can-opener-sg ---------------------------------------------------------------
    CIDR                 Proto & Ports   Time range                     Active
    88.115.164.95/32     tcp:8080-8080   1332684317-1332684317          True
    88.115.164.95/32     tcp:22-22       1332684317-1332684317          True

Finally, if you want to be prudent and close any holes after you no
longer need them, you can just use --remove to make them go away::

   $ can-opener --remove
   REMOVE: can-opener-sg: 88.115.164.95/32 -> tcp:22-22
   REMOVE: can-opener-sg: 88.115.164.95/32 -> tcp:8080-8080

Unless you have changed the default tags, you could also do this to
zap **all** holes that have been created by you (but only by you)::

   $ can-opener --remove -p all all

The ``all`` values refer to *all ports* (``-p all``) and *all
addresses* (``all`` -- equivalent to ``0.0.0.0/0``).

How to set up
-------------

There are three things to consider when using can opener:

**First**, you need to have AWS access keys set up correctly. You can
specify AWS access keys either via environmental variables
``AWS_ACCESS_KEY_ID`` and ``AWS_SECRET_ACCESS_KEY`` or use
command-line options ``-A``, ``--access-key-id``, ``-S`` and
``--secret-access-key``.

To use other than the default AWS region, you can use either
``AWS_REGION`` environmental variable or ``-R``/``--region`` command
line option.

**Secondly**, the AWS access keys must have access to necessary
security groups and SimpleDB domains. This is only an issue if you are
using IAM. If not, there's no problem here, move on.

OTOH if you *are* using IAM, then keep the following in mind:

- The user must have the following actions allowed to manage required
  security groups:

  - ``ec2:AuthorizeSecurityGroupIngress``
  - ``ec2:CreateSecurityGroup``
  - ``ec2:DescribeRegions``
  - ``ec2:DescribeSecurityGroups``
  - ``ec2:RevokeSecurityGroupIngress``

- The following are required to manipulate and update SimpleDB to
  store information about the firewall accesses given:

  - ``sdb:CreateDomain``
  - ``sdb:DeleteAttributes``
  - ``sdb:GetAttributes``
  - ``sdb:PutAttributes``
  - ``sdb:Select``

If you are picky about ``ec2:CreateSecurityGroup`` and
``sdb:CreateDomain`` permissions, you can leave them out. Then you
just need to manually create both the used security groups and the
SimpleDB domain that is used (by default, can opener will create these
if they do not exist).

EC2 permissions cannot be unfortunately narrowed down to individual
security group level, e.g. when you grant the above permissions (which
are required for can opener to work), you're granting them to all of
that account's security groups. For *SimpleDB* this is possible by
specifying the correct resource ARN,
e.g. ``arn:aws:sdb:**REGION**:**ACCOUNT ID**:domain/can-opener-sdb``.

There's also useful shortcut in can opener to create a new IAM group
with correct permissions, the ``can-opener-sg`` and SimpleDB domain
``can-opener-sdb``::

    $ can-opener --initialize
    XXX TODO GRAB CLEAN OUTPUT XXX

(If you want to destroy old group, user and policies, use
``--initialize-destructive``. It comes without undo.)

**Thirdly** you **must** include ``can-opener-sg`` in all instances
you wish to use can opener with. See below for some discussion and
suggestions on how to set up security groups for your instances.


Security group setup for can opener
-----------------------------------

Each AWS instance can have **more than one security group** and it is
**not possible to alter list of security groups** after instance
creation (apart from VPC instances).

Thus you **must include** the can opener security group
(``can-opener-sg``) in your instance when it is created. If not, you
may use existing security group (``-s``, ``--security-group`` option)
but this is not recommended.

Also include **at least one other security group** that is not managed
by can opener. You should use this security group for static firewall
rules. Do not use can opener's security group for other purposes.
(Non-can opener rules will get zapped with ``--manage --tags ''``!)

Let's take a Jenkins CI instance with repository stored in GitHub as
an example:

* Run ``can-opener --initialize`` and distribute the created keys to
  developers
* Create instance with two (or more) security groups:
  ``can-opener-sg`` and ``jenkins-sg``.
* Either set up elastic IP or use DNS update to give your instance a
  fixed IP address or a known DNS address (GitHub needs this).
* Set up Jenkins in the instance. Remember to include GitHub plugin.
* Allow GitHub's known IP addresses to access Jenkins (port 8080)
  either via AWS management console, command-line tools to even can
  opener: ``can-opener -p 8080 -s jenkins-sg 207.97.227.253
  50.57.128.197``
* Configure GitHub post-receive hook to publish to the Jenkins' URL,
  like ``http://**your.instance.dns**:8080/jenkins/github-webhook/``.
* Set up can opener to periodically run as ``can-opener --manage
  --tags ''`` (cron or Jenkins periodic job are both valid options).
  Tune ``--lifetime`` to suit your needs (default is 8 hours).
