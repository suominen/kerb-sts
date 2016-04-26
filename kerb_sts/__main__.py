import argparse
import logging
import os
import subprocess
import sys
import time

from kerb_sts import handler
from kerb_sts import ntlmcredentials
from kerb_sts import config


def _get_default_credentials_filename():
    """
    Returns the path to the default AWS credentials file. This
    is where the temporary access keys will be stored unless
    otherwised specified by the user.
    :return: The path to the default credentials file
    """

    home = os.path.expanduser('~')
    awsconfigfile = '/.aws/credentials'

    # Don"t use `os.path.join` because on Windows it will eat the directory
    # path when a drive letter is return as part of the home directory.
    filename = home + awsconfigfile

    abs_filename = os.path.abspath(filename)
    return abs_filename


def main():
    parser = argparse.ArgumentParser(description="Generates 1 hour temporary AWS IAM credentials.")
    parser.add_argument('--adfs', help="ADFS IdP domain name (defaults to {0})".format(config.adfs),
                        dest='adfs', default=config.adfs)
    parser.add_argument('-c', '--credentials_file', help="AWSCLI credentials file (defaults ~/.aws/credentials)",
                        dest='credentials_file', default=_get_default_credentials_filename())
    parser.add_argument('--daemon', help="Run as a daemon. This will auto-renew credentials every half hour",
                        dest='daemon', action='store_true', default=False)
    parser.add_argument('-r', '--default_role', help="Name of the Role to use as the default",
                        dest='default_role', default=None)
    parser.add_argument('-d', '--domain', help="AD Domain if using a Kerberos keytab or NTLM auth",
                        dest='domain', default=None)
    parser.add_argument('--keytab', help="The Kerberos keytab if generating a temporary Kerberos token",
                        dest='keytab', default=None)
    parser.add_argument('--list', help="List the available roles",
                        dest='list', action='store_true', default=False)
    parser.add_argument('-p', '--password', help="AD Password if generating a temporary Kerberos token",
                        dest='password', default=None)
    parser.add_argument('--refresh', help="Time to wait (minutes) between refreshing the tokens.",
                        dest='refresh', default=30)
    parser.add_argument('--region', help="AWS Region for STS (defaults to {0})".format(config.region),
                        dest='region', default=config.region)
    parser.add_argument('-u', '--username', help="AD Username if generating a temporary Kerberos token",
                        dest='username', default=None)
    parser.add_argument('-v', '--verbose', help="Turns on debug logging",
                        dest="verbose", action='store_true', default=None)

    options = parser.parse_args()

    if options.verbose:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.INFO
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p', level=logging_level)
    logging.debug("logging level set to {0}".format(logging_level))

    if options.adfs:
        url = options.adfs
    else:
        url = config.adfs
    logging.debug("adfs url set to {0}".format(url))

    credentials = None
    authtype = 'kerberos'
    if options.username and options.domain:
        if options.keytab:
            # Setup a temporary credentials cache
            credentials_cache = os.path.join(os.getcwd(), 'credentials_cache')
            os.environ['KRB5CCNAME'] = credentials_cache

            # Call kinit to generate a Kerberos ticket for the given username and keytab
            try:
                subprocess.check_output(['kinit', '-c', credentials_cache, '-kt', options.keytab,
                                         "{0}@{1}".format(options.username, options.domain)])
            except subprocess.CalledProcessError as e:
                sys.exit(1)

            authtype = 'keytab'
            logging.debug("set to use kerberos keytab")

        elif options.password:
            # No keytab was provided but a username was. Fall back to NTLM auth
            authtype = 'ntlm'
            credentials = ntlmcredentials.NtlmCredentials(username=options.username, password=options.password,
                                                          domain=options.domain)
            logging.debug("set to use ntlm auth")

        else:
            logging.error("username and domain provided but no password or keytab was provided. Cannot auth as user")
            sys.exit(1)

    else:
        logging.debug("no username or domain given. using kerberos auth")
        try:
            subprocess.check_output(['klist', '-s'])
        except subprocess.CalledProcessError as e:
            logging.info("no kerberos ticket found. running kinit")
            try:
                subprocess.check_output(['kinit'])
            except subprocess.CalledProcessError as e:
                logging.error("failed to generate a kerberos ticket")
                sys.exit(1)

    while True:
        if options.list:
            logging.info("=== listing available roles ===")
        else:
            logging.info("=== generating tokens ===")
        logging.info("region: {0}".format(options.region))
        logging.info("url: {0}".format(url))
        logging.info("credentials file: {0}".format(options.credentials_file))
        logging.info("auth type: {0}".format(authtype))

        if credentials:
            logging.info("user: {0}".format(credentials.username))

        if credentials or (options.domain and options.keytab):
            logging.info("domain: {0}".format(options.domain))

        try:
            h = handler.KerberosHandler()
            h.handle_sts_by_kerberos(options.region, url, options.credentials_file,
                                     options.default_role, options.list, credentials)
            logging.info("=== completed ===")

        except Exception as ex:
            logging.error(ex)
            sys.exit(1)

        if not options.daemon:
            break

        # Sleep for 30 minutes
        time.sleep(60 * options.refresh)

if __name__ == "__main__":
    main()
