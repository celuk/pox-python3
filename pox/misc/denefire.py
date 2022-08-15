# Final Skeleton
#
# Hints/Reminders from Lab 4:
# 
# To send an OpenFlow Message telling a switch to send packets out a
# port, do the following, replacing <PORT> with the port number the 
# switch should send the packets out:
#
#    msg = of.ofp_flow_mod()
#    msg.match = of.ofp_match.from_packet(packet)
#    msg.idle_timeout = 30
#    msg.hard_timeout = 30
#
#    msg.actions.append(of.ofp_action_output(port = <PORT>))
#    msg.data = packet_in
#    self.connection.send(msg)
#
# To drop packets, simply omit the action.
#

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Final (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

  def send_msg_to_host(self, dst_ip, host_ip, msg, packet_in, of):
    # each switch is connected to two hosts
    # if destination ip is equal to first host ip
    if dst_ip == host_ip:
      self.send_msg(1, msg, packet_in, of)
    # if not then send it to second host ip
    else:
      self.send_msg(2, msg, packet_in, of)

  def send_msg(self, port, msg, packet_in, of):
    msg.data = packet_in
    action = of.ofp_action_output(port = port)
    msg.actions.append(action)
    self.connection.send(msg)

  def do_final (self, packet, packet_in, port_on_switch, switch_id):
    # port_on_switch represents the port that the packet was received on.
    # switch_id represents the id of the switch that received the packet
    # (for example, s1 would have switch_id == 1, s2 would have switch_id == 2, etc...)
    # each floor switch is connected to only two hosts on port 1 and 2
    # core switch is connected to all floor switches on port 3
    # untrusted host is connected directly to core switch
    
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet)
    msg.idle_timeout = 30
    msg.hard_timeout = 30
    ipv4_packet = packet.find('ipv4')
    icmp_packet = packet.find('icmp')
    server_ip = '10.0.0.1'
    untrusted_ip = '10.0.0.7'

    # if not icmp packet and ipv4 packet flood out
    if icmp_packet is None and ipv4_packet is None:
      print("NOT ICMP PACKET")
      self.send_msg(of.OFPP_FLOOD, msg, packet_in, of)
    # if icmp packet
    elif icmp_packet:
      print("ICMP PACKET")
      src_ip = ipv4_packet.srcip        # source ip in ipv4 packet
      # drop all icmp traffic from untrusted host to any node
      if src_ip == untrusted_ip:
        self.connection.send(msg)
      else:
        self.send_msg(of.OFPP_FLOOD, msg, packet_in, of)
    # if ipv4 packet and not icmp packet
    else:
      dst_ip = ipv4_packet.dstip        # destination ip in ipv4 packet
      src_ip = ipv4_packet.srcip        # source ip in ipv4
      print("dst", dst_ip)
      print("IP PACKET")
      # if core switch received the packet then forward to floor switch or server switch or untrusted host
      if switch_id > 5:
        j = 0
        # rule: drop all ip traffic from untrusted host to data server
        if src_ip == untrusted_ip and dst_ip == server_ip:
          self.connection.send(msg)
        # if data server ip 
        elif dst_ip == server_ip:
          self.send_msg(6, msg, packet_in, of)
        # if untrusted host ip (core switch is conencted directly to untrusted host through port 5)
        elif dst_ip == untrusted_ip:
          self.send_msg(5, msg, packet_in, of)
        # find the switch through destination ip then send msg to port that connects core switch to that switch
        else:
          for i in range(1, 5):
            host_ips = ['10.0.'+str(i+j)+'.'+str(i+j)+'0', '10.0.'+str(i+j+1)+'.'+str(i+j+1)+'0']   # e.g [10.0.1.10, 10.0.2.20]
            if dst_ip in host_ips:
              self.send_msg(i, msg, packet_in, of)
            j = j + 1
      # if floor switch received the packet from core switch then forward to host 
      # floor switches receive packet from core switch on port 3
      elif switch_id <= 5 and port_on_switch == 3:
        j = 0
        # if data center switch then send to server host
        if switch_id == 5:
            self.send_msg_to_host(dst_ip, server_ip, msg, packet_in, of)
        # check which switch received the packet then send the msg to respective host
        else:
          # to find which one of the hosts (host1, host2) connected to switch to send
          # send to either port1 or port2
          for i in range(1, 5):
            if switch_id == i:
              host_ip = '10.0.'+str(i+j)+'.'+str(i+j)+'0'   
              self.send_msg_to_host(dst_ip, host_ip, msg, packet_in, of)
            j = j + 1
      
      # if floor switch received the packet from host then forward to core switch 
      elif switch_id <= 5 and port_on_switch < 3:
        self.send_msg(3, msg, packet_in, of)


  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_final(packet, packet_in, event.port, event.dpid)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Final(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
