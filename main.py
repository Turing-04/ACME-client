import argparse
from https_server import HTTPSServer
from acme_client import ACMEClient
from shutdown_server import ShutdownServer


def banner():    
    print("""
 █████╗  ██████╗███╗   ███╗███████╗    ██████╗ ██████╗  ██████╗      ██╗███████╗ ██████╗████████╗
██╔══██╗██╔════╝████╗ ████║██╔════╝    ██╔══██╗██╔══██╗██╔═══██╗     ██║██╔════╝██╔════╝╚══██╔══╝
███████║██║     ██╔████╔██║█████╗      ██████╔╝██████╔╝██║   ██║     ██║█████╗  ██║        ██║   
██╔══██║██║     ██║╚██╔╝██║██╔══╝      ██╔═══╝ ██╔══██╗██║   ██║██   ██║██╔══╝  ██║        ██║   
██║  ██║╚██████╗██║ ╚═╝ ██║███████╗    ██║     ██║  ██║╚██████╔╝╚█████╔╝███████╗╚██████╗   ██║   
╚═╝  ╚═╝ ╚═════╝╚═╝     ╚═╝╚══════╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚════╝ ╚══════╝ ╚═════╝   ╚═╝                                                                                                                                                                                                                                                                                                                    
""")
    
def download_certificate(certificate):
    with open("certificate.pem", "w") as f:
        f.write(certificate)
    print("\033[92m Certificate successfully downloaded \033[0m")


def main():
    banner()
    
    option_parser = argparse.ArgumentParser(description="ACME-project NetSec 2023")

    option_parser.add_argument("challenge type", choices=["http01", "dns01"])
    option_parser.add_argument("--dir",required=True, dest="DIR_URL",help="the directory URL of the \
        ACME server that should be used.")    
    option_parser.add_argument("--record", required=True, type=str,  dest="IPv4_ADDRESS", help="IPv4 address which \
        must be returned by your DNS server for all A-record queries.")
    option_parser.add_argument("--domain", required=True, action="append", help="the domain for  which to request \
        the certificate. If multiple --domain flags are present, a single certificate for multiple domains should \
            be requested. Wildcard domains have no special flag and are simply denoted by, e.g., *.example.net")
    option_parser.add_argument("--revoke", action="store_true", help="(Optional) If present, your application should \
        immediately revoke the certificate after obtaining it.\
        In both cases, your application should start its HTTPS server and set it up to use the newly obtained certificate.")
    
    
    
    options = option_parser.parse_args()
    
    DIR_URL = options.DIR_URL
    IPv4_ADDRESS = options.IPv4_ADDRESS
    domains = options.domain
    revoke = options.revoke
    challenge_type = options.__getattribute__("challenge type")
    
    print("-------------------------------------------------------------", end="\n\n")
    print('\033[94m' + "Starting ACME client with the following options:"+ '\033[0m')
    print("Challenge type: ", challenge_type)
    print("ACME server directory URL: ", DIR_URL)
    print("DNS Record IP: ", IPv4_ADDRESS)
    print("Domains:: ", domains)
    print("Revoke: ", revoke, end="\n\n")
    
    #print(options)
    
    # à revoir ordre de démarrage et démarrage ACME client puis gestion des challenges
    
    """
    if challenge_type == "http01":
        http_server = HTTP_server(challenge_type, DIR_URL, IPv4_ADDRESS, domains, revoke)
        http_server.run()
    elif challenge_type == "dns01":
        dns_server = DNS_Server(challenge_type, DIR_URL, IPv4_ADDRESS, domains, revoke)
        dns_server.run()
        """
        
    print("-------------------------------------------------------------", end="\n\n")
    
    
    # call ACME client
    # do the setup phase
    # do the challenge phase (launch DNS + add TXT record or HTTP route)
    # do the certificate request phase
    # (do the revoke phase)   
    
    acme_client = ACMEClient(IPv4_ADDRESS, DIR_URL, domains, revoke, challenge_type)
    
    print('\033[94m' + "ACME client: GET directory" + '\033[0m')
    acme_client.get_directory()
    print("-------------------------------------------------------------")

    print('\033[94m' + "ACME client: POST newAccount" + '\033[0m')    
    acme_client.get_newAccount()
    print("\n-------------------------------------------------------------")
    
    print('\033[94m' + "ACME client: POST newOrder" + '\033[0m')
    acme_client.get_newOrder()
    print("\n-------------------------------------------------------------")
    print('\033[94m' + "ACME client: Retrieving Challenges" + '\033[0m')

    n = acme_client.get_challenges()
    print(f"Succesfully retrieved {n} challenges, challenge type: \033[92m {challenge_type} \033[0m")
    
    print("\n-------------------------------------------------------------")
    print('\033[94m' + "ACME client: Validating Challenges" + '\033[0m')
    
    acme_client.validate_challenge()
    
    print("\033[92m Challenge validation completed \033[0m")
    print("\n-------------------------------------------------------------")
    
    print("\033[94m ACME client: Getting certificate \033[0m")
    acme_client.get_certificate()
    certificate = acme_client.retrieve_certificate()
    download_certificate(certificate)
    
    print("\033[92m Certificate successfully retrieved ! \033[0m")
    print("\n-------------------------------------------------------------")
    
    print("\033[94m Setting up HTTPS server with newly generated certificate \033[0m")
    https_server = HTTPSServer(IPv4_ADDRESS, certificate, port=5001)
    https_server.start()
    
    print("\033[92m HTTPS server successfully started ! \033[0m")
    print("\n-------------------------------------------------------------")
    
    print("\033[94m Starting Shutdown Server \033[0m")
    
    shutdown_server = ShutdownServer(IPv4_ADDRESS, port=5003)
    shutdown_server.start()
    
    print("\033[92m Shutdown server successfully started ! \033[0m")
    print("\n-------------------------------------------------------------")
    
    if(revoke):
        print("\033[94m Revoking certificate \033[0m")
        acme_client.revoke_certificate()
        print("\033[92m Certificate successfully revoked ! \033[0m")
        print("\n-------------------------------------------------------------")
    

if __name__ == "__main__":
    main()


