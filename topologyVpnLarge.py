from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel


class SshVpnTopo(Topo):
    def build(self):
        # Switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        # Clients on switch 1
        h1 = self.addHost('h1', ip='10.0.0.1/20', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/20', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/20', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/20', mac='00:00:00:00:00:04')

        # Clients on switch 2
        h11 = self.addHost('h11', ip='10.0.0.11/20', mac='00:00:00:00:00:11')
        h12 = self.addHost('h12', ip='10.0.0.12/20', mac='00:00:00:00:00:12')
        h13 = self.addHost('h13', ip='10.0.0.13/20', mac='00:00:00:00:00:13')
        h14 = self.addHost('h14', ip='10.0.0.14/20', mac='00:00:00:00:00:14')

        # Server node
        h99 = self.addHost('h99', ip='10.0.0.99/20', mac='00:00:00:00:00:99')

        # Links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)

        self.addLink(h11, s2)
        self.addLink(h12, s2)
        self.addLink(h13, s2)
        self.addLink(h14, s2)

        # Hierarchy: s1 & s2 → s3 → server
        self.addLink(s1, s3)
        self.addLink(s2, s3)
        self.addLink(s3, h99, bw=100)


def run():
    net = Mininet(
        topo=SshVpnTopo(),
        controller=None,
        switch=OVSSwitch,
        autoSetMacs=False,
        autoStaticArp=True
    )

    # OpenDaylight controller
    c0 = net.addController(
        'c0', controller=RemoteController,
        ip='192.168.2.4',
        port=6653
    )

    net.start()

    # Start SSH daemon on server h99
    server = net.get('h99')
    server.cmd('mkdir -p /var/run/sshd')
    server.cmd('/usr/sbin/sshd')

    print("*** Network up. h99 sshd running.")
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
