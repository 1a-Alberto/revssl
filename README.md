# revssl



## introduccion
Revssl se creó principalmente para automatizar la idea de shell inverso de OpenSSL [desde aqui](https://medium.com/@int0x33/day-43-reverse-shell-with-openssl-1ee2574aa998) y empaquetarla en un único script. Puede generar agentes tanto para Linux como para Windows, proporcionando un canal de control remoto seguro y encriptado. Todavía estoy trabajando en la implementación de OSX. Este código no es perfecto, así que no dudes en abrir nuevas ediciones y contribuir :D

## Uso
```
usage: revssl [-h] [-i] [-e <encryption>] [-d <days>] [-l <lhost>]
              [-p <lport>] [-k <keyname>] [-c <certname>] [-p <platform>]
              [-o] [-n <outfile>] [-s <domain>] [-r]
options:
 -h     Show help message
 -i     Initiate listener in OpenSSL
 -e <encryption>
        Choose encryption type (default: rsa:4096)
 -d <days>
        Set certificates lifetime
 -l <lhost>
        Set listening host (default: 192.168.1.102)
 -p <port>
        Set listening port (default: 443)
 -k <keyname>
        Set name of generated key file (default: key.pem)
 -c <certname>
        Set name of generated cert file (default: cert.pem)
 -p <platform>
        Select agent platform (windows or linux, default: linux)
 -s <domain>
        Domain name for Windows Powershell agent (default: domain.xyz)
 -o     Write agent to a file
 -n <outfile>
        Select name of the agent file (default: openssl_revshell)
 -r     Remove generated certificates after established session
```

