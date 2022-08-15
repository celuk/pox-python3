from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr

''' Add your imports here ... '''
from pox.lib.util import str_to_bool
import time

log = core.getLogger()

''' Add your global variables here ... '''



class Firewall (EventMixin):

	def __init__ (self):
		self.listenTo(core.openflow)
		log.debug("Enabling Firewall Module")

	def _handle_ConnectionUp (self, event):    
		''' Add your logic here ... '''
		print("hello")
		log.debug("Connection %s"%(event.connection,))
		self.connection = event.connection
		
		
		dpidstr = dpidToStr(event.connection.dpid)

		self.send_packet(1, "00:00:00:00:00:01", "00:00:00:00:00:07", dpidstr)
		self.send_packet(2, "00:00:00:00:00:02", "00:00:00:00:00:05", dpidstr)
		self.send_packet(3, "00:00:00:00:00:03", "00:00:00:00:00:06", dpidstr)
		self.send_packet(4, "00:00:00:00:00:04", "00:00:00:00:00:03", dpidstr)



	def send_packet(self,sid,src,dest,dpidstr):
		print("Src is ",str(src))
		print("Src is ",str(EthAddr(src)))
		match = of.ofp_match()
		msg = of.ofp_flow_mod()
		msg.priority = 32768
		msg.match.dl_src = EthAddr(src)
		msg.match.dl_dst = EthAddr(dest)
		self.connection.send(msg)
	

def launch ():
	'''
	Starting the Firewall module
	'''
	print("Starting firewall!!")
	core.registerNew(Firewall)

