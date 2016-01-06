# foutun
Foo-over-UDP tunneling

This is a work in progress. It is linux only. It requires the 'fou' module to be
loaded on both client and server. Usage example:

On server

    fou-server <server-peer-ip>

On client

    fou-client <server-ip> <client-peer-ip> -n <tunnel-iface-name>
