import sys
import optparse
import subprocess
import pandas as pd
from scapy.utils import rdpcap
from scapy.utils import wrpcap
from scapy.all import *
from scapy.layers.inet import IP, ICMP
import random
import base64
import csv

#Field and length of them supported
FIELD_LENGTH = {
	"TIMING": 1
}

ICMP_REQ_REP = {
	"REQUEST": 8,
	"REPLY": 0
}

def process_command_line(argv):
	parser = optparse.OptionParser()
	parser.add_option('-r', '--pcap', help='Specify the pcap to inject.', action='store', type='string', dest='pcap')
	parser.add_option('-w', '--output', help='Specify the output pcap file.', default='output.pcap', action='store', type='string', dest='output')
	settings, args = parser.parse_args(argv)
	return settings, args


def read_attack(attack_to_read, field):
	print("Reading the attack...")
	dim_field = FIELD_LENGTH[field]
	file_in_string = str(attack_to_read)
	attack_in_bits = ''.join(format(ord(bit), '08b') for bit in file_in_string)
	#Division in chunks of 'dim_field' size
	attack_in_chunks = [attack_in_bits[i:i+dim_field] for i in range(0, len(attack_in_bits), dim_field)]
	#If TIMING i need at least one packet before the secret to understand if the secret
	#starts with 1 or 0
	if field == "TIMING":
		attack_in_bits_tmp = '0' + attack_in_bits
		attack_in_bits = attack_in_bits_tmp
		attack_in_chunks.insert(0, '0')
	print("Number of packets needed: " + str(len(attack_in_chunks)))
	print("Number of bits needed: " + str(len(attack_in_bits)))
	return attack_in_chunks, str(len(attack_in_chunks)), str(len(attack_in_bits))

def find_flows(pcap_to_read, number_packets):
	#Creation of csv file where each line is composed of three-tuple src and dst for each packet 
	print("Creating tmp files...")
	create_tmp_csv = "tshark -r " + pcap_to_read + " -T fields -e ip.src -e ip.dst -e ip.proto -Y 'icmp.type == " + str(ICMP_REQ_REP["REQUEST"]) + "' -E header=y -E separator=, > tmp.csv"
	process = subprocess.Popen(create_tmp_csv, shell=True, stdout=subprocess.PIPE)
	process.wait()
	#Count of packets that compose each flow, grouping by src, dst and fl
	df = pd.read_csv('tmp.csv')
	df_final = df.groupby(['ip.src', 'ip.dst', 'ip.proto']).size().to_frame('#pkts').reset_index()
	#Deleting of csv file
	delete_tmp_csv = "rm tmp.csv"
	process = subprocess.Popen(delete_tmp_csv, shell=True, stdout=subprocess.PIPE)
	process.wait()
	print("Deleting tmp files...")
	#Adding INDEX column name
	df.index.name = "INDEX"
	#Return flows which contains at leats 'number_of_packets' packets
	df_final = df_final[['ip.src', 'ip.dst', 'ip.proto', '#pkts']]
	df_final = df_final.fillna('-')
	return df_final.loc[df_final['#pkts'] >= number_packets]

def inject(pcap, source, destination, protocol, targeted_field, attack_in_chunks):
	print("Reading input pcap. This might take few minutes...")
	pkts = rdpcap(pcap)
	secret_index = 0
	wire_len = []
	index = 0
	#Delay and number of delays to add for timing CC
	delta = 10
	n = 0

	resulting_pcap_file = settings.output

	print("Injecting...")
	for x in range(len(pkts)):
		wire_len.append(pkts[x].wirelen)
		# Stego content only into icmp requests. Change '8' to '0' for icmp replies
		if ICMP in pkts[x] and pkts[x][ICMP].type == 8:
			#Search for the correct flow
			if source == pkts[x][IP].src and destination == pkts[x][IP].dst and protocol == pkts[x][IP].proto:
				#If there is still something to inject
				if secret_index < len(attack_in_chunks):
					if targeted_field == "TIMING":
						if int(attack_in_chunks[secret_index], 2) == 1:
							n += 1
					secret_index += 1
				#Modify the time of each packet. In case of non-timing CCs, n = 0 and nothing happens. Otherwise, 
				#the time change according to n and delta.
				pkts[x].time += n * delta
			#Modify the time of packets in the opposite direction. This is necessary for timing CCs to respect the order
			#of received packet.
		if ICMP in pkts[x] and pkts[x][ICMP].type == 0:	
			if source == pkts[x][IP].dst and destination == pkts[x][IP].src and protocol == pkts[x][IP].proto:
				pkts[x].time += n * delta
		pkts[x].wirelen = wire_len[index]
		index += 1
		# Recalculate checksum
		del pkts[x][ICMP].chksum
		#WARNING: check if the linktype is what is needed
		wrpcap(resulting_pcap_file, pkts[x], append=True, linktype=1)
	print("Injection succesfully finished!")
	return resulting_pcap_file

def flow_selection(flows, number):
	source = flows.loc[number]['ip.src']
	destination = flows.loc[number]['ip.dst']
	protocol = 1
	return source, destination, protocol


settings, args = process_command_line(sys.argv)
attack_in_chunks, lengthp, lengthb = read_attack("w", "TIMING")
print(attack_in_chunks)
flows = find_flows(settings.pcap, len(attack_in_chunks))
if len(flows) > 0:
	print('-' * 25)
	print("CONVERSATIONS FOUND")
	print(flows.head(50))
	print("Only the first 50 conversations are shown (if present).")
	print('-' * 25)
	while True:
		operation = input("Choose the flow by its index (leave it blank for the first flow or 'r' for a random choice): ")
		if operation.strip().isdigit():
			what_flow = int(operation)
			if not what_flow in flows.index:
				print("Invalid flow index")
				continue
			else:
				source, destination, protocol = flow_selection(flows, what_flow)
				break
		elif operation == 'r':
			rnd_flow = random.choice(flows.index.tolist())
			print('Flow ' + str(rnd_flow) + ' is chosen.')
			source, destination, protocol = flow_selection(flows, rnd_flow)
			break
		elif operation == '':
			print('First flow is chosen.')
			first_flow = flows.index.tolist()[0]
			source, destination, protocol = flow_selection(flows, first_flow)
			break
		else:
			print("This operation is not supported!")
	print('-' * 25)
	resulting_pcap_file = inject(settings.pcap, source, destination, protocol, "TIMING", attack_in_chunks)
else:
	print("No conversations with enough packets are found in this pcap!")
























