# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology.api import get_switch, get_link, get_host, get_all_host
from ryu.topology import event, switches 
import networkx as nx
import json
import logging
import struct
from webob import Response
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import ether
from ryu.app.ofctl.api import get_datapath

import msgpack
import hmac
import hashlib
import json
import socket
import hashlib
from scapy.all import Ether, IP, UDP, Raw
from os.path import expanduser


NUMBER_OF_SWITCH_PORTS = 3

conf_path = expanduser("~")+'/conf.json'


class ZodiacSwitch(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	_CONTEXTS = {'wsgi': WSGIApplication}

	def __init__(self, *args, **kwargs):
		super(ZodiacSwitch, self).__init__(*args, **kwargs)
		wsgi = kwargs['wsgi']
		self.topology_api_app = self
		self.net = nx.DiGraph()
		self.nodes = {}
		self.links = {}
		self.mac_to_port = {}
		self.mac_to_dpid = {}
		self.port_to_mac = {}
		self.ip_to_mac = {}
		self.port_occupied = {}
		self.GLOBAL_VARIABLE = 0

		# Define the margin for which the ctr is accepted
		self.ctr_margin = 5
		self.expected_ctr = 0
		self.client_shared_key = 0
 		self.controller_shared_key = 0

 		self.controller_mac = "4e:4e:4e:4e:4e:4e"
 		self.controller_ip = "10.0.0.100"

 		self.servers_ip = ['10.0.0.2']

 		self.flows_expire_in = 30 # time taken to expire a flow (idle_timeout)

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# install table-miss flow entry
		#
		# We specify NO BUFFER to max_len of the output action due to
		# OVS bug. At this moment, if we specify a lesser number, e.g.,
		# 128, OVS will send Packet-In with invalid buffer_id and
		# truncated packet data. In that case, we cannot output packets
		# correctly.  The bug has been fixed in OVS v2.1.0.
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
											ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)

		# Send ARP Request to servers
		for server in self.servers_ip:
			self.send_arp(datapath, 1, self.controller_mac, self.controller_ip, 0, server, ofproto.OFPP_FLOOD)

	def add_flow(self, datapath, priority, match, actions, idle_timeout=0, buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
												actions)]
		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
									priority=priority, match=match, idle_timeout=idle_timeout,
									instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, priority=priority, idle_timeout=idle_timeout,
									match=match, instructions=inst)
		datapath.send_msg(mod)

	def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
		# If it is an ARP request
		if opcode == 1:
			self.logger.info("\n[S"+str(datapath.id)+" SENT ARP REQUEST] From: " + srcIp + " Looking for: " + dstIp + "...\n")
			targetMac = "00:00:00:00:00:00"
			targetIp = dstIp
		# If it is an ARP reply
		elif opcode == 2:
			self.logger.info("\n[S"+str(datapath.id)+" SENT ARP REPLY] From: " + srcIp + " To: " + dstIp + "...\n")
			targetMac = dstMac
			targetIp = dstIp

		e = ethernet.ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
		a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=opcode, src_mac=srcMac, src_ip=srcIp, dst_mac=targetMac, dst_ip=targetIp)
		p = Packet()
		p.add_protocol(e)
		p.add_protocol(a)
		p.serialize()
	
		actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
		out = datapath.ofproto_parser.OFPPacketOut(
				datapath=datapath,
				buffer_id=0xffffffff,
				in_port=datapath.ofproto.OFPP_CONTROLLER,
				actions=actions,
				data=p.data)
		datapath.send_msg(out)


	# Given the unpacked authentication message,
	# returns True if it is correct (it is a dict and contains at least the required fields),
	# False otherwise
	def is_req_auth_correct(self, auth_msg):
	    correct = False
	    
	    expected_fields = set(['server', 'dport', 'ctr', 'tcp_udp', 'my_ip', 'hmac'])
	    
	    # check if it is a dictionary
	    if type(auth_msg) is dict:
	        # Check that it contains all the expected fields
	        if expected_fields.issubset(auth_msg.keys()):
	            correct = True

	    return correct

	# Given the an auth request/reply message returns True if it is authenticated
	def is_msg_authenticated(self, rcv_message, hash_key):
	    rcv_hmac = rcv_message['hmac']

	    # Compute the HMAC of the modified authentication request (hmac=0)
	    rcv_message['hmac'] = 0
	    modified_json = msgpack.packb(rcv_message)
	    print(hash_key.hexdigest())
	    computed_hmac = hmac.new(key=hash_key.digest(), digestmod=hashlib.sha256)
	    computed_hmac.update(modified_json)
	    message_digest = computed_hmac.digest()

	    # Compare the computed HMAC with the received one
	    return hmac.compare_digest(rcv_hmac, message_digest)

	# Generate and returns an auth reply ready to be sent
	def make_auth_reply(self, code, expected_ctr, shared_key):
	    # json request
	    reply_data_dict = {
	      'code': code,
	      'expected_ctr': expected_ctr,
	      'hmac': 0
	    }

	    # Serialize request_data_dict
	    reply_data_raw = msgpack.packb(reply_data_dict)

	    # Generate a message authentication code of request_data_raw based on 
	    # the shared_key and secure hashing algorithm SHA256 using hmac module
	    hmac1 = hmac.new(key=shared_key.digest(), digestmod=hashlib.sha256)
	    hmac1.update(reply_data_raw)
	    message_digest = hmac1.digest()
	    
	    # Insert the computed HMAC in hmac value of the request dictionary
	    reply_data_dict['hmac'] = message_digest
	    
	    # Serialize request_data_dict with the updated HMAC
	    auth_reply = msgpack.packb(reply_data_dict)
	    
	    return auth_reply


	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		# If you hit this you might want to increase
		# the "miss_send_length" of your switch
		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("packet truncated: only %s of %s bytes",
						ev.msg.msg_len, ev.msg.total_len)
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			# ignore lldp packet
			return
		dst = eth.dst
		src = eth.src
		dpid_src = datapath.id
		
		
		# TOPOLOGY DISCOVERY------------------------------------------

		switch_list = get_switch(self.topology_api_app, None)   
		switches=[switch.dp.id for switch in switch_list]
		if self.GLOBAL_VARIABLE == 0:
			for s in switches:
				for switch_port in range(1, NUMBER_OF_SWITCH_PORTS+1):
					self.port_occupied.setdefault(s, {})
					self.port_occupied[s][switch_port] = 0
		self.net.add_nodes_from(switches)
		links_list = get_link(self.topology_api_app, None)
		links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		links_=[(link.dst.dpid,link.src.dpid,link.dst.port_no) for link in links_list]
		for l in links_:
			if l[0] in self.port_occupied.keys():
				if l[2] in self.port_occupied[l[0]].keys():
					self.port_occupied[l[0]][l[2]] = 1
			
	# MAC LEARNING-------------------------------------------------
		
		self.mac_to_port.setdefault(dpid_src, {})
		self.port_to_mac.setdefault(dpid_src, {})
		self.mac_to_port[dpid_src][src] = in_port
		self.mac_to_dpid[src] = dpid_src
		self.port_to_mac[dpid_src][in_port] = src

	# HANDLE ARP PACKETS--------------------------------------------
		   
		if eth.ethertype == ether_types.ETH_TYPE_ARP:

			arp_packet = pkt.get_protocol(arp.arp)
			arp_dst_ip = arp_packet.dst_ip
			arp_src_ip = arp_packet.src_ip

			# self.logger.info("It is an ARP packet")	
			# If it is an ARP request
			if arp_packet.opcode == 1:
				self.logger.info("\n[S"+str(dpid_src)+" RCV ARP REQUEST] From: " + arp_src_ip + " Looking for: " + arp_dst_ip + "...\n")

				# if sent by controller itself drop
				if arp_src_ip == self.controller_ip:
					return

				if arp_dst_ip == self.controller_ip:
					srcIp = arp_dst_ip
					dstIp = arp_src_ip
					srcMac = self.controller_mac
					dstMac = src
					outPort = in_port
					opcode = 2

					self.send_arp(datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort)

				elif arp_dst_ip in self.ip_to_mac:
					# self.logger.info("The address is inside the IP TO MAC table")
					srcIp = arp_dst_ip
					dstIp = arp_src_ip
					srcMac = self.ip_to_mac[arp_dst_ip]
					dstMac = src
					outPort = in_port
					opcode = 2
					self.send_arp(datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
					# self.logger.info("packet in %s %s %s %s", srcMac, srcIp, dstMac, dstIp)
				else:
					# self.logger.info("The address is NOT inside the IP TO MAC table")
					srcIp = arp_src_ip
					dstIp = arp_dst_ip
					srcMac = src
					dstMac = dst
					# learn the new IP address
					self.ip_to_mac.setdefault(srcIp, {})
					self.ip_to_mac[srcIp] = srcMac
					# Send and ARP request to all the switches
					opcode = 1
					for id_switch in switches:
						#if id_switch != dpid_src:
						datapath_dst = get_datapath(self, id_switch)
						for po in range(1,len(self.port_occupied[id_switch])+1):
							if self.port_occupied[id_switch][po] == 0:
								outPort = po
								if id_switch == dpid_src:
									if outPort != in_port:
										self.send_arp(datapath_dst, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
								else:
									self.send_arp(datapath_dst, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
	
			else: # ARP REPLY
				self.logger.info("\n[S"+str(dpid_src)+" RCV ARP REPLY] From: " + arp_src_ip + "\n")

				srcIp = arp_src_ip
				dstIp = arp_dst_ip
				srcMac = src
				dstMac = dst
				if arp_dst_ip in self.ip_to_mac:
					# learn the new IP address
					self.ip_to_mac.setdefault(srcIp, {})
					self.ip_to_mac[srcIp] = srcMac
							# Send and ARP reply to the switch
				opcode = 2
				outPort = self.mac_to_port[self.mac_to_dpid[dstMac]][dstMac]
				datapath_dst = get_datapath(self, self.mac_to_dpid[dstMac])
				self.send_arp(datapath_dst, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
					 
				   
		# HANDLE IP PACKETS-----------------------------------------------
			
		ip4_pkt = pkt.get_protocol(ipv4.ipv4)
		if ip4_pkt:


			src_ip = ip4_pkt.src
			dst_ip = ip4_pkt.dst
			src_MAC = src
			dst_MAC = dst

			# Learn IP to MAC association of the src
			self.ip_to_mac[ip4_pkt.src] = src

			proto  = str(ip4_pkt.proto)
			sport = "0"
			dport = "0" 
			if proto == "6":
				tcp_pkt = pkt.get_protocol(tcp.tcp)
				sport = str(tcp_pkt.src_port)
				dport = str(tcp_pkt.dst_port)
				   
			if proto == "17":
				udp_pkt = pkt.get_protocol(udp.udp)
				sport = str(udp_pkt.src_port)
				dport = str(udp_pkt.dst_port)
					
			self.logger.info("Packet in switch: %s, source IP: %s, destination IP: %s, From the port: %s", dpid_src, src_ip, dst_ip, in_port)
			# self.logger.info("Packet in switch: %s, source MAC: %s, destination MAC: %s, From the port: %s", dpid_src, src, dst, in_port)
			
			# --------------------------------------------------------------------- AUTH CONTROL ---
			authorised = False
			if src_ip not in self.servers_ip and proto == "17":
				auth_request = pkt.protocols[-1]

				# ----- Analyze the received packet -----
				# Unpack the received auth message
				unpacked_auth_request = msgpack.unpackb(auth_request)

				# Check its correctness (it is a json with all the required fields)
				correct = self.is_req_auth_correct(unpacked_auth_request)

				

				rcv_ctr = unpacked_auth_request['ctr']

				if correct:
				    authenticated = self.is_msg_authenticated(unpacked_auth_request, client_shared_key)
				    if authenticated:
				        print('Authenticated message:')
				        #print("\t", unpacked_auth_request)
				        print(rcv_ctr, self.expected_ctr)
				        # Check if ctr is valid
				        if rcv_ctr in range(self.expected_ctr, self.expected_ctr + self.ctr_margin):
				            code = '202 Authentication Accepted'
				            self.expected_ctr = rcv_ctr + 1
				            authorised = True
				        else: # authenticated but not valid ctr -> not accepted
				            code = '449 Retry With'
				    else: # message not authenticated
				        code = '401 Unauthorized'
				else: # received message not correct 
				    code = '400 Bad Request'
				
				print('Code: {}'.format(code))    
				# ----- Send the auth reply -----
				# Generate auth reply
				auth_reply = self.make_auth_reply(code, self.expected_ctr, controller_shared_key)

				# Create the packet ready to be sent
				reply_pkt = Ether(src=dst, dst=src)/IP(src=dst_ip, dst=src_ip) / UDP(sport=int(dport), dport=int(sport)) / Raw(load=auth_reply)
				reply_pkt.build()
				# send the reply back to the client
				actions = [datapath.ofproto_parser.OFPActionOutput(in_port, 0)]
				out = datapath.ofproto_parser.OFPPacketOut(
						datapath=datapath,
						buffer_id=0xffffffff,
						in_port=datapath.ofproto.OFPP_CONTROLLER,
						actions=actions,
						data=bytes(reply_pkt)
						)
				
				datapath.send_msg(out)

			# Servers in the network are authorised to communicate
			if src_ip in self.servers_ip:
				print('Packet from server -> authorised')
				authorised = True

			# if authorised install the path
			if authorised:
				# if dst_MAC == 'ff:ff:ff:ff:ff:ff':
				# 	return
				try:
					if src_ip not in self.servers_ip:
						datapath_dst = get_datapath(self, self.mac_to_dpid[self.ip_to_mac[unpacked_auth_request['server']]])	
						
					else:
						datapath_dst = get_datapath(self, self.mac_to_dpid[dst])	
					
				except:
					self.logger.info(" --- No informations on how to reach %s", unpacked_auth_request['server'])
					return

				dpid_dst = datapath_dst.id				
				self.logger.info(" --- Destination present on switch: %s", dpid_dst)
					
				# Shortest path computation
				path = nx.shortest_path(self.net,dpid_src,dpid_dst)
				self.logger.info(" --- Shortest path: %s", path)
					
				# Set the flows for different cases
				if src_ip not in self.servers_ip:
					dst_ip = unpacked_auth_request['server']
					dst_MAC = self.ip_to_mac[unpacked_auth_request['server']]
				if len(path) == 1:
					In_Port = self.mac_to_port[dpid_src][src]
					Out_Port = self.mac_to_port[dpid_dst][dst_MAC]	
					actions_1 = [datapath.ofproto_parser.OFPActionOutput(Out_Port)]
					actions_2 = [datapath.ofproto_parser.OFPActionOutput(In_Port)]
					# restrict the access only to specific port asked
					if src_ip not in self.servers_ip:
						if unpacked_auth_request['tcp_udp'] == 'tcp':
							match_1 = parser.OFPMatch(in_port=In_Port, eth_dst=dst_MAC, eth_type = 0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=6, tcp_dst=unpacked_auth_request['dport'])
							match_2 = parser.OFPMatch(in_port=Out_Port, eth_dst=src, eth_type = 0x0800, ipv4_src=dst_ip, ipv4_dst=src_ip, ip_proto=6, tcp_src=unpacked_auth_request['dport'])
						else:
							match_1 = parser.OFPMatch(in_port=In_Port, eth_dst=dst_MAC, eth_type = 0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=17, udp_dst=unpacked_auth_request['dport'])
							match_2 = parser.OFPMatch(in_port=Out_Port, eth_dst=src, eth_type = 0x0800, ipv4_src=dst_ip, ipv4_dst=src_ip, ip_proto=17, udp_src=unpacked_auth_request['dport'])
					else:
						match_1 = parser.OFPMatch(in_port=In_Port, eth_dst=dst_MAC)
						match_2 = parser.OFPMatch(in_port=Out_Port, eth_dst=src)
					self.add_flow(datapath, 1, match_1, actions_1, idle_timeout=self.flows_expire_in)
					self.add_flow(datapath, 1, match_2, actions_2, idle_timeout=self.flows_expire_in)

					actions = [datapath.ofproto_parser.OFPActionOutput(Out_Port)]
					data = msg.data
					pkt = packet.Packet(data)
					eth = pkt.get_protocols(ethernet.ethernet)[0]
					# self.logger.info(" --- Changing destination mac to %s" % (eth.dst))
					pkt.serialize()
					out = datapath.ofproto_parser.OFPPacketOut(
						datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
						actions=actions, data=pkt.data)
					datapath.send_msg(out)
									
				elif len(path) >= 2:
					datapath_src = get_datapath(self, path[0])
					datapath_dst = get_datapath(self, path[len(path)-1])
					dpid_src = datapath_src.id
					#self.logger.info("dpid_src  %s", dpid_src)
					dpid_dst = datapath_dst.id
					#self.logger.info("dpid_dst  %s", dpid_dst)
					In_Port_src = self.mac_to_port[dpid_src][src]
					#self.logger.info("In_Port_src  %s", In_Port_src)
					In_Port_dst = self.mac_to_port[dpid_dst][dst_MAC]
					#self.logger.info("In_Port_dst  %s", In_Port_dst)
					Out_Port_src = self.net[path[0]][path[1]]['port']
					#self.logger.info("Out_Port_src  %s", Out_Port_src)
					Out_Port_dst = self.net[path[len(path)-1]][path[len(path)-2]]['port']
					#self.logger.info("Out_Port_dst  %s", Out_Port_dst)
					
					actions_1_src = [datapath.ofproto_parser.OFPActionOutput(Out_Port_src)]
					# restrict the access only to specific port asked
					if src_ip not in self.servers_ip:
						if unpacked_auth_request['tcp_udp'] == 'tcp':
							match_1_src = parser.OFPMatch(in_port=In_Port_src, eth_type = 0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=6, tcp_dst=unpacked_auth_request['dport'])
						else:
							match_1_src = parser.OFPMatch(in_port=In_Port_src, eth_type = 0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=17, udp_dst=unpacked_auth_request['dport'])
					else:
						match_1_src = parser.OFPMatch(in_port=In_Port_src, eth_type = 0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
					self.add_flow(datapath_src, 1, match_1_src, actions_1_src, idle_timeout=self.flows_expire_in)
					
					actions_2_src = [datapath.ofproto_parser.OFPActionOutput(In_Port_src)]
					# restrict the access only to specific port asked
					if src_ip not in self.servers_ip:
						if unpacked_auth_request['tcp_udp'] == 'tcp':
							match_2_src = parser.OFPMatch(in_port=Out_Port_src, eth_type = 0x0800, ipv4_src=dst_ip, ipv4_dst=src_ip, ip_proto=6, tcp_src=unpacked_auth_request['dport'])
						else:
							match_2_srcc = parser.OFPMatch(in_port=Out_Port_src, eth_type = 0x0800, ipv4_src=dst_ip, ipv4_dst=src_ip, ip_proto=17, udp_src=unpacked_auth_request['dport'])
					else:
						match_2_src = parser.OFPMatch(in_port=Out_Port_src, eth_type = 0x0800, ipv4_src=dst_ip, ipv4_dst=src_ip)
					self.add_flow(datapath_src, 1, match_2_src, actions_2_src, idle_timeout=self.flows_expire_in)
					self.logger.info("Install the flow on switch %s", path[0])
					
					actions_1_dst = [datapath.ofproto_parser.OFPActionOutput(Out_Port_dst)]
					
					match_1_dst = parser.OFPMatch(in_port=In_Port_dst, eth_type = 0x0800, ipv4_src=dst_ip, ipv4_dst=src_ip)
					self.add_flow(datapath_dst, 1, match_1_dst, actions_1_dst, idle_timeout=self.flows_expire_in)
					
					actions_2_dst = [datapath.ofproto_parser.OFPActionOutput(In_Port_dst)]
					match_2_dst = parser.OFPMatch(in_port=Out_Port_dst, eth_type = 0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
					self.add_flow(datapath_dst, 1, match_2_dst, actions_2_dst, idle_timeout=self.flows_expire_in)
					self.logger.info("Install the flow on switch %s", path[len(path)-1])
					
					if len(path) > 2:
						for i in range(1, len(path)-1):
							self.logger.info("Install the flow on switch %s", path[i])
							In_Port_temp = self.net[path[i]][path[i-1]]['port']
							Out_Port_temp = self.net[path[i]][path[i+1]]['port']
							dp = get_datapath(self, path[i])
							actions_1 = [dp.ofproto_parser.OFPActionOutput(Out_Port_temp)]
							actions_2 = [dp.ofproto_parser.OFPActionOutput(In_Port_temp)]
							if src_ip not in self.servers_ip:
								if unpacked_auth_request['tcp_udp'] == 'tcp':
									match_1 = parser.OFPMatch(in_port=In_Port_temp, eth_type = 0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=6, tcp_dst=unpacked_auth_request['dport'])
									match_2 = parser.OFPMatch(in_port=Out_Port_temp, eth_type = 0x0800, ipv4_src=dst_ip, ipv4_dst=src_ip, ip_proto=6, tcp_src=unpacked_auth_request['dport'])
								else:
									match_1 = parser.OFPMatch(in_port=In_Port_temp, eth_type = 0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=17, udp_dst=unpacked_auth_request['dport'])
									match_2 = parser.OFPMatch(in_port=Out_Port_temp, eth_type = 0x0800, ipv4_src=dst_ip, ipv4_dst=src_ip, ip_proto=17, udp_src=unpacked_auth_request['dport'])

							else:
								match_1 = parser.OFPMatch(in_port=In_Port_temp, eth_type = 0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
								match_2 = parser.OFPMatch(in_port=Out_Port_temp, eth_type = 0x0800, ipv4_src=dst_ip, ipv4_dst=src_ip)
							self.add_flow(dp, 1, match_1, actions_1, idle_timeout=self.flows_expire_in)
							self.add_flow(dp, 1, match_2, actions_2, idle_timeout=self.flows_expire_in)

				# Send the packet to the original switch if coming from server
				if src_ip in self.servers_ip:
					path_port = self.net[path[0]][path[1]]['port']
					actions = [datapath.ofproto_parser.OFPActionOutput(path_port)]
					data = msg.data
					pkt = packet.Packet(data)
					eth = pkt.get_protocols(ethernet.ethernet)[0]
					# change the mac address of packet
					eth.src = self.ip_to_mac[src_ip] 
					eth.dst = self.ip_to_mac[dst_ip] 
					# self.logger.info(" --- Changing destination mac to %s" % (eth.dst))
					pkt.serialize()
					out = datapath.ofproto_parser.OFPPacketOut(
					datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
						actions=actions, data=pkt.data)
					datapath.send_msg(out)

				else:
					if not authorised:
						self.logger.info("Packet not authorised from %s to %s", src_ip, dst_ip)


	@set_ev_cls(event.EventSwitchEnter)
	def get_topology_data(self, ev):
		switch_list = get_switch(self.topology_api_app, None)
		switches=[switch.dp.id for switch in switch_list]
		self.net.add_nodes_from(switches)
		links_list = get_link(self.topology_api_app, None)
		links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
		self.net.add_edges_from(links)	
		

app_manager.require_app('ryu.app.ws_topology')
app_manager.require_app('ryu.app.ofctl_rest')
app_manager.require_app('ryu.app.gui_topology.gui_topology')	


# Get master key and counter values from conf.json
with open(conf_path, 'r') as config_file:
    config_json = json.load(config_file)
    master_key = config_json["master_key"]
    expected_ctr = config_json["next_ctr"]

# Get shared keys from master key
client_shared_key = hashlib.sha256(str.encode(str(master_key+'0')))
controller_shared_key = hashlib.sha256(str.encode(str(master_key+'1')))
print("Obtained the following shared keys:\n\tclient {}\n\tcontroller {}".format(client_shared_key.hexdigest(), controller_shared_key.hexdigest()))