"""TwoWayTopology

Four switches in a ring topology with two host connected at opposite sides of the ring:
            /--- s2 ---\
  h1 --- s1              s4 --- h2
            \--- s3 ---/
Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.link import TCLink

class TwoWayTopology( Topo ):

    def build( self ):

        # Add hosts and switches
        leftHost = self.addHost( 'h1' )
        leftHost2 = self.addHost('h3')
        rightHost = self.addHost( 'h2' )

        leftSwitch = self.addSwitch( 's1' )
        upSwitch = self.addSwitch( 's2' )
        downSwitch = self.addSwitch('s3')
        rightSwitch = self.addSwitch('s4')

        # Add links
        self.addLink(leftHost, leftSwitch, cls=TCLink, bw=20)
        self.addLink(leftHost2, leftSwitch, cls=TCLink, bw=20)
        self.addLink(leftSwitch, upSwitch, cls=TCLink, bw=10)
        self.addLink(leftSwitch, downSwitch, cls=TCLink, bw=10)
        self.addLink(upSwitch, rightSwitch, cls=TCLink, bw=10)
        self.addLink(downSwitch, rightSwitch, cls=TCLink, bw=10)
        self.addLink(rightSwitch, rightHost, cls=TCLink, bw=20)


topos = { 'mytopo': ( lambda: TwoWayTopology() ) }
