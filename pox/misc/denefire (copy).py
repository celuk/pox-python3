from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
import pox.lib.packet as pkt
from pox.lib.addresses import EthAddr, IPAddr



log = core.getLogger()


class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        self.firewall = {}
        log.info("Starting SDN Firewall")


        self.FTP_PORT      = 21
        self.HTTP_PORT     = 80
        self.TELNET_PORT   = 23
        self.SMTP_PORT     = 25


    def pushRuleToSwitch (self, src, dst, ip_proto, app_proto, duration):
        # creating a switch flow table entry
        msg = of.ofp_flow_mod()
        msg.priority = 20
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))

        # creating a match structure
        match = of.ofp_match()

        # set packet ethernet type as IP
        match.dl_type = 0x800;

        # Setting the duration of the rule
        d = int(duration)
        if d == 0:
           action = "del"
        else:
           action = "add"

        if not isinstance(d, tuple):
            d = (d,d)
        msg.idle_timeout = d[0]
        msg.hard_timeout = d[1]

        # IP protocol match
        if ip_proto == "tcp":
           match.nw_proto = pkt.ipv4.TCP_PROTOCOL
        if ip_proto == "udp":
           match.nw_proto = pkt.ipv4.UDP_PROTOCOL
        elif ip_proto == "icmp":
           match.nw_proto = pkt.ipv4.ICMP_PROTOCOL
        elif ip_proto == "igmp":
           match.nw_proto = pkt.ipv4.IGMP_PROTOCOL



        #Application protocol match
        if app_proto == "ftp":
           match.tp_dst = self.FTP_PORT
        elif app_proto == "http":
           match.tp_dst = self.HTTP_PORT
        elif app_proto == "telnet":
           match.tp_dst = self.TELNET_PORT
        elif app_proto == "smtp":
           match.tp_dst = self.SMTP_PORT


        # flow rule for src:host1 dst:host2
        if src != "any":
            match.nw_src = IPAddr(src)
        if dst != "any":
           match.nw_dst = IPAddr(dst)
        msg.match = match

        if action == "del":
                msg.command=of.OFPFC_DELETE
                msg.flags = of.OFPFF_SEND_FLOW_REM
                self.connection.send(msg)
        elif action == "add":
                self.connection.send(msg)


        # flow rule for src:host2 dst:host1
        if dst != "any":
           match.nw_src = IPAddr(dst)
        if src != "any":
           match.nw_dst = IPAddr(src)
        msg.match = match

        if action == "delete":
                msg.command=of.OFPFC_DELETE
                msg.flags = of.OFPFF_SEND_FLOW_REM
                self.connection.send(msg)
        elif action == "add":
                self.connection.send(msg)


    def addFirewallRule (self, src=0, dst=0, ip_proto=0, app_proto=0, duration = 0, value=True):
        if (src, dst, ip_proto, app_proto, duration) in self.firewall:
            log.warning("Rule exists: drop: src:%s dst:%s ip_proto:%s app_proto:%s duration:%s", src, dst, ip_proto, app_proto, duration)
        else:
            self.firewall[(src, dst, ip_proto, app_proto, duration)]=value
            self.pushRuleToSwitch(src, dst, ip_proto, app_proto, duration)
            log.info("Rule added: drop: src:%s dst:%s ip_proto:%s app_proto:%s duration:%s", src, dst, ip_proto, app_proto, duration)


    def delFirewallRule (self, src=0, dst=0, ip_proto=0, app_proto=0, duration = 0, value=True):
        if (src, dst, ip_proto, app_proto) in self.firewall:
            del self.firewall[(src, dst, ip_proto, app_proto)]
            self.pushRuleToSwitch(src, dst, ip_proto, app_proto, duration)
            log.info("Rule Deleted: drop: src:%s dst:%s ip_proto:%s app_proto:%s", src, dst, ip_proto, app_proto)
        else:
            log.error("Rule doesn't exist: drop: src:%s dst:%s ip_proto:%s app_proto:%s", src, dst, ip_proto, app_proto)


    def showFirewallRules (self):
        log.info("")
        log.info("")
        log.info("!!! Displaying Firewall Rules !!!")
        rule_num = 1
        for item in self.firewall:
             if item[4] != "0":
                log.info("Rule %s: src:%s dst:%s ip_proto:%s app_proto:%s", rule_num, item[0], item[1], item[2], item[3])
             rule_num += 1
            
    def _handle_ConnectionUp (self, event):
        

        self.connection = event.connection

        
        #self.addFirewallRule('10.0.0.1', '10.0.0.2', 'udp', 'any', 10000)
        self.addFirewallRule('10.0.0.2', '10.0.0.3', 'icmp', 'any', 10000)
        #self.addFirewallRule('10.0.0.1', '10.0.0.3', 'tcp', 'http', 10000)

        self.showFirewallRules()
        log.info("")
        log.info("")
        log.info("Firewall rules pushed on the switch id: %s", dpidToStr(event.dpid))

def launch ():
    core.registerNew(Firewall)


        
        
