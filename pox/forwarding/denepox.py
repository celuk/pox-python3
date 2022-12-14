
#DPID = DataPath ID provded to switches that communicate with a controller
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_bool
import time

log = core.getLogger()

#import argparse
#parser = argparse.ArgumentParser(description='QoS Service')
#parser.add_argument('-q', action='store_true')
#options = parser.parse_args()

isQoS = False #options.q

class LearningSwitch (object):
	print("\n-------------------------")
	print("----Bil452 Controller----")
	print("-------------------------")
	
	def __init__ (self, connection):
		# Switch we'll be adding L2 learning switch capabilities to
		self.connection = connection
		connection.addListeners(self)
		self.macToPortMap = {}

	def _handle_PacketIn (self, event):
		#print(dpidToStr(event.dpid))
		#Parsing Incoming packet
		packet = event.parsed
		#Updating mac-table to port-mapping
		self.macToPortMap[packet.src] = event.port
		#Flooding Function
		def flood():
			#print("[+] Debug: Flooding")
			msg = of.ofp_packet_out()
			msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
			msg.in_port = event.port
			msg.buffer_id = event.ofp.buffer_id
			self.connection.send(msg)
		#Dropping Function
		def drop():
			#print("[+] Debug: Dropping Packets")
			msg = of.ofp_flow_mod()
			msg.match = of.ofp_match.from_packet(packet)
			msg.idle_timeout = 10
			msg.hard_timeout = 30
			msg.buffer_id = event.ofp.buffer_id
			self.connection.send(msg)
		#Forwarding Function
		def forward():
			#print("[+] Debug: Forwarding")
			#TODO - WILL CODE
			msg = of.ofp_flow_mod()
			msg.match.dl_src = packet.src
			msg.match.dl_dst = packet.dst
			msg.idle_timeout = 10
			msg.hard_timeout = 30
			msg.actions.append(of.ofp_action_output(port = outport))
			msg.buffer_id = event.ofp.buffer_id
			self.connection.send(msg)
		#Check if Packet has not been mapped
		if packet.dst not in self.macToPortMap:
			#switch does not know egress port
			#Flood the packet
			#log.debug("[-] Debug: Port for %s unknown -- Flooding" % (packet.dst,))
			#print("[+] Debug: Port for %s unknown -- Flooding" % (packet.dst,))
			flood()
		#If it has then forward the packet unless its destination is the same port its been received on
		else:
			#Forward packet if SW knows outprt
			outport = self.macToPortMap[packet.dst]
			if outport == event.port:
				#log.warning("[-] Same port for packet from %s -> %s on %s/ Drop." %
									#(packet.src, packet.dst, outport), dpidToStr(event.dpid))
				#print("[-] Same port for packet from %s -> %s on %s/ Drop." % (packet.src, packet.dst, outport))
				drop()
				return
			#log.debug("[F] Installing flow for %s port:%i -> %sport:%i" % 
							#(packet.src, event.port, packet.dst, outport), dpidToStr(event.dpid))
			#print("[F] Debug: Installing flow:\n    %s port:%i -> %s port:%i \n    on Switch:" % (packet.src, event.port, packet.dst, outport), dpidToStr(event.dpid))
			#log.debug("[+] Port for %s known -- Forwarding" % (packet.dst,))
			#print("[+] Debug: Port for %s known -- Forwarding" % (packet.dst,))
			#Forward the packet if in MacToPortMap map
			forward()
"""Waits for OVSC switches and makes them learning switches"""
"""
class l2_learning (object):
	
	
	
	def __init__ (self):
		core.openflow.addListeners(self)

	def _handle_ConnectionUp(self,event):
		log.debug("Connection %s" % (event.connection,))
		LearningSwitch(event.connection)
"""

class l2_learning (object):
	def __init__ (self): #def launch (reactive = False):
		reactive = False
		if reactive:
			core.openflow.addListenerByName("PacketIn", self._handle_PacketIn)
			log.info("Reactive hub running.")
		else:
			core.openflow.addListenerByName("ConnectionUp", self._handle_ConnectionUp)
			log.info("Proactive hub running.")
	
	def _handle_ConnectionUp (self, event):
		"""
		Be a proactive hub by telling every connected switch to flood all packets
		"""
		print(dpidToStr(event.dpid))
		msg = of.ofp_flow_mod()
		msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
		event.connection.send(msg)
		log.info("Hubifying %s", dpidToStr(event.dpid))
		LearningSwitch(event.connection)


	def _handle_PacketIn (self, event):
		"""
		Be a reactive hub by flooding every incoming packet
		"""
		msg = of.ofp_packet_out()
		msg.data = event.ofp
		msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
		event.connection.send(msg)

def launch (q=False):
	global isQoS
	isQoS = q
	
	print(isQoS)
	"""Starts an L2 learning switch."""
	core.registerNew(l2_learning)
	



	
	
