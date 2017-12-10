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
You only need to pass the tuple {protocol, dtls} in Options list intead of 
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

I wanted to separate the control plane from 
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

Here is wishvpn aimed architecture (of course is not so now)
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

The packet forwarding model
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
Thank you, dear judge, to waste your time trying to dig in this crappy code! :)

Build
-----

    $ rebar3 compile

Build release
-----

    $ rebar3 as prod tar
    
by colrack
