wishvpn
=====

SSL/VPN client/server written in Erlang

During the weekend of the spwanfest (2017) I just wanted to experiment with
the OTP ssl app. In particular I wanted to try the DTLS part.
(See https://en.wikipedia.org/wiki/Datagram_Transport_Layer_Security and
https://tools.ietf.org/html/rfc6347).
The ssl app seems to support DTLS and OTP guys at Ericsson are currently 
working on it (see https://github.com/erlang/otp/commits/master/lib/ssl and 
filter for `DTLS`). In OTP 20.1, the API is the same as the SSL/TLS.
You only need to pass the tuple {protocol, dtls} instead of 
{protocol, tls} in the `connect/X` and `listen/X` functions (client and server 
respectively).
DTLS is applicable both for UDP and SCTP; here we are using UDP sockets.
The idea is to establish a secure tunnel over 2 peers using DTLS and encapsulate
IP packets from one peer to the other to form a virtual private network.
I used the excellent https://github.com/msantos/tunctl to interact with 
tun devices. You can find an example there where 2 peers are connected over 
Erlang native distribution and the same concepts as here are applied, except
the fact that there is no encryption in the established tunnel. Of course you 
can enable SSL for Erlang Distribution.

Here is the protocol stack for user data in wishvpn.
```
┌─────────┐         ┌────────┐
│   IP    │─────────│   IP   │
├─────────┤         ├────────┤
│UDP/DTLS │─────────│UDP/DTLS│
├─────────┤         ├────────┤
│   IP    │─────────│   IP   │
├─────────┤         ├────────┤
│   L2    │─────────│   L2   │
├─────────┤         ├────────┤
│   L1    │─────────│   L1   │
└─────────┘         └────────┘
```

In future I want to separate the signalling data (used for establish a session)
from the user data.
To establish a DTLS data session, the client communicate with the server over 
GRPC. The server authenticate the client using eg username+password; the server 
release the data to let the client authenticate in the data session.

```
┌────────┐         ┌────────┐
│  GRPC  │─────────│  GRPC  │
├────────┤         ├────────┤
│TCP/SSL │─────────│TCP/SSL │
├────────┤         ├────────┤
│   IP   │─────────│   IP   │
├────────┤         ├────────┤
│   L2   │─────────│   L2   │
├────────┤         ├────────┤
│   L1   │─────────│   L1   │
└────────┘         └────────┘
```

Here is wishvpn aimed architecture (of course is not like this now).
A web server backed with cowboy is serving REST API that let a local client
(eg a Command line interface app) control the main application that runs as as
a system service.

```
    ┌─────────────────────────────────┐    ┌─────────────────────────────────┐
    │         wishvpn client          │    │         wishvpn server          │
    │                  ┌────────────┐ │    │ ┌────────────┐                  │
    │                  │GRPC/SSL/TCP│ │    │ │GRPC/SSL/TCP│                  │
    │                  │   socket   │◀┼────┼▶│   socket   │                  │
    │                  └────────────┘ │    │ └────────────┘                  │
    │   ┌────────┐     ┌────────────┐ │    │ ┌────────────┐     ┌────────┐   │
    │   │Tun/Tap │     │IP/DTLS/UDP │ │    │ │IP/DTLS/UDP │     │Tun/Tap │   │
◀───┼──▶│ Device │◀───▶│   socket   │◀┼────┼▶│   socket   │◀───▶│ Device │◀──┼───▶
    │   └────────┘     └────────────┘ │    │ └────────────┘     └────────┘   │
    │       ┌───────────────────────┐ │    │ ┌───────────────────────┐       │
    │       │       HTTP API        │ │    │ │       HTTP API        │       │
    │       │     (app control)     │ │    │ │     (app control)     │       │
    │       └───────────────────────┘ │    │ └───────────────────────┘       │
    └───────────────────▲─────────────┘    └─────────────▲───────────────────┘
                        │                                │
                        │                                │

                  CLI / Browser                    CLI / Browser
```

The packet forwarding model will be as below.
Now only PDR and FAR are used.

```
            ┌───────────────────────────────────────────────────────────────────────────┐
            │                                  ┌──────┐      ┌────┐   ┌────┐    ┌────┐  │
            │                               ┌─▶│ PDR  │─────▶│FARs│──▶│QERs│───▶│URRs│  │
            │                   match       │  └──────┘      └────┘   └────┘    └────┘  │
 Packet In  │  session         session      │  ┌──────┐                                 │ Packet Out
───────────▶│  lookup  ────▶     with     ──┘  │ PDR  │        Apply rules to packet    │───────────▶
            │                  highest         └──────┘                                 │
            │                 precedence       ┌──────┐                                 │
            │                                  │ PDR  │                                 │
            │                                  └──────┘                                 │
            └───────────────────────────────────────────────────────────────────────────┘
```

```
PDR = Packet Detection Rule
FAR = Forwarding Action Rule
QER = QoS Enforcement Rule
URR = Usage Report Rule
```

Thank you, dear judge, to waste your time trying to dig in this crappy code! :)

Build
-----

    $ rebar3 compile

Build release
-----

    $ rebar3 as prod tar --sys_config config/sys1.config
    
If you really want to try the code
-----

You need 2 peers to test the app. You can for example use your host and a virtual 
machine in your host, or 2 VMs hosted in your computer.
The code runs on Linux/MacOS/Windows. I tested it on Linux and MacOS. On Linux
you don't need to install anything if your kernel supports TUN/TAP. In MacOS you 
need TUN/TAP drivers (you can install them with `brew install caskroom/cask/tuntap`)
or just dowload from http://tuntaposx.sourceforge.net . Beware of permissions 
(see https://github.com/msantos/tunctl to set privileges).
I developed the code on the Mac using docker and 2 virtualbox VMs.
Install docker-machine and create 2 VMs:

    $ docker-machine create -d virtualbox vm1
    $ docker-machine create -d virtualbox vm2
    
Check in `sys1.config` and `sys2.config` if IPs are set correctly.
They are set to `{ip, "192.168.99.100"}` and `{remote_ip, "192.168.99.100"}`.

My first VM act as the server and has `192.168.99.100` assigned.
The second VM act as the client and has `192.168.99.101` assigned.
The 2 VMs reach each other using this subnet.
You can find your VM IP running

    $ docker-machine ip vm1
    192.168.99.100
and

    $ docker-machine ip vm2
    192.168.99.101
    
In your host start shell #1 and start the server:

    $ eval $(docker-machine env vm1)
    $ docker run --name wishvpn -it --rm --cap-add=NET_ADMIN \
      --device /dev/net/tun --net=host -v ${HOME}/.ssh:/root/.ssh \
      -v ${PWD}:${PWD} -w ${PWD} erlang:20.1 \
      rebar3 shell --sname wpn --setcookie secret --apps wishvpn \
      --config config/sys1.config

Unfortunately you have to assign IP manually 

    $ docker exec -it wishvpn ip addr add 10.8.0.1/24 dev tun0
    $ docker exec -it wishvpn ip link set tun0 up

Start shell #2

    $ eval $(docker-machine env vm2)
    $ docker run --name wishvpn -it --rm --cap-add=NET_ADMIN \
      --device /dev/net/tun --net=host -v ${HOME}/.ssh:/root/.ssh \
      -v ${PWD}:${PWD} -w ${PWD} erlang:20.1 \
      rebar3 shell --sname wpn --setcookie secret --apps wishvpn \
      --config config/sys2.config

Unfortunately you have to assign IP manually

    $ docker exec -it wishvpn ip addr add 10.8.0.2/24 dev tun0
    $ docker exec -it wishvpn ip link set tun0 up

      
If everything is set up correctly you can ping VM1 from VM2 and viceversa.

    vm1$ docker exec -it wishvpn ping 10.8.0.2 -c 3
    PING 10.8.0.2 (10.8.0.2): 56 data bytes
    64 bytes from 10.8.0.2: icmp_seq=0 ttl=64 time=1.304 ms
    64 bytes from 10.8.0.2: icmp_seq=1 ttl=64 time=1.582 ms
    64 bytes from 10.8.0.2: icmp_seq=2 ttl=64 time=1.936 ms
    --- 10.8.0.2 ping statistics ---
    3 packets transmitted, 3 packets received, 0% packet loss
    round-trip min/avg/max/stddev = 1.304/1.607/1.936/0.259 ms
    
and

    vm2$ docker exec -it wishvpn ping 10.8.0.1 -c 3
    PING 10.8.0.1 (10.8.0.1): 56 data bytes
    64 bytes from 10.8.0.1: icmp_seq=0 ttl=64 time=1.322 ms
    64 bytes from 10.8.0.1: icmp_seq=1 ttl=64 time=1.561 ms
    64 bytes from 10.8.0.1: icmp_seq=2 ttl=64 time=1.461 ms
    --- 10.8.0.1 ping statistics ---
    3 packets transmitted, 3 packets received, 0% packet loss
    round-trip min/avg/max/stddev = 1.322/1.448/1.561/0.098 ms


[Wireshark capture](docs/wishvpn_dtls_wireshark.png)

by colrack
