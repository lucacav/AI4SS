from PIL import Image
import numpy as np
import random
import optparse
import sys
import binascii


def process_command_line(argv):
	parser = optparse.OptionParser()
	parser.add_option('-i', '--input', help='Specify the input image.', action='store', type='string', dest='input')
	parser.add_option('-s', '--secret', help='Specify the secret to imbed in the input image.', action='store', type='string', dest='secret')
	parser.add_option('-c', '--channels', help='Specify the number of channels to use.', action='store', type='string', dest='channels', default='RGB')
	parser.add_option('-b', '--bits', help='Specify the number of bits per channel to use.', action='store', type='int', dest='bits', default=1)
	parser.add_option('-p', '--pixel', help='Specify the starting pixel.', action='store', type='int', dest='starting_pixel', default=1)
	parser.add_option('-o', '--output', help='Specify the output image.', action='store', type='string', dest='output', default='output.png')

	settings, args = parser.parse_args(argv)
	return settings, args

def parse_image(image_path):
	with Image.open(image_path) as im:
		#it returns RGB or RGBA (if alpha channel is present)
		mode = im.mode
		#alpha channel
		a = []
		if len(mode) == 3:
			r,g,b = im.split()
			alpha = []
		else:
			r,g,b, a = im.split()
			alpha = np.array(a).reshape(-1)
		red   = np.array(r).reshape(-1)
		green = np.array(g).reshape(-1)
		blue  = np.array(b).reshape(-1)
		width, height = im.size


	red_in_bits   = []
	green_in_bits = []
	blue_in_bits  = []
	alpha_in_bits = []

	for x in range(len(red)):
		red_in_bits.append('{0:08b}'.format(red[x]))
		green_in_bits.append('{0:08b}'.format(green[x]))
		blue_in_bits.append('{0:08b}'.format(blue[x]))
		if len(alpha) != 0:
			alpha_in_bits.append('{0:08b}'.format(alpha[x]))

	return red_in_bits, green_in_bits, blue_in_bits, alpha_in_bits, width, height

def read_secret(secret_path):
	secret_in_bits = ''.join(format(ord(bit), '08b') for bit in secret_path)
	return secret_in_bits

def encode_LSB(r, g, b, alpha, secret_in_chunks, channels, pixel_index):
	index = 0
	for x in range(len(r)):
		if x >= pixel_index - 1:
			if index >= len(secret_in_chunks):
				break
			if index < len(secret_in_chunks):
				if "R" in channels:
					r[x] = r[x][:-len(secret_in_chunks[index])] + secret_in_chunks[index]
					index += 1
			if index < len(secret_in_chunks):
				if "G" in channels:
					g[x] = g[x][:-len(secret_in_chunks[index])] + secret_in_chunks[index]
					index += 1
			if index < len(secret_in_chunks):
				if "B" in channels:
					b[x] = b[x][:-len(secret_in_chunks[index])] + secret_in_chunks[index]
					index += 1

	new_pixels_list = []
	tmp_list = []
	for x in range(len(r)):
		tmp_red_int = int(r[x], 2)
		tmp_green_int = int(g[x], 2)
		tmp_blue_int = int(b[x], 2)
		if len(alpha) != 0:
			tmp_alpha_int = int(alpha[x], 2)
			tmp_list.append((tmp_red_int, tmp_green_int, tmp_blue_int, tmp_alpha_int))
		else:
			tmp_list.append((tmp_red_int, tmp_green_int, tmp_blue_int))
		if len(tmp_list) == width:
			new_pixels_list.append(tmp_list)
			tmp_list = []
	return new_pixels_list


def decode_LSB(r, g, b, bits, channels, pixel_index):
	extracted_secret_in_bits = []
	for x in range(len(r)):
		if x >= pixel_index - 1:
			if "R" in channels:
				extracted_secret_in_bits.append(r[x][-bits:])
			if "G" in channels:
				extracted_secret_in_bits.append(g[x][-bits:])
			if "B" in channels:
				extracted_secret_in_bits.append(b[x][-bits:])
	return extracted_secret_in_bits


def decode_OceanLotus_LSB(r, g, b, channels, pixel_index):
	extracted_secret_in_bits = []
	for x in range(len(r)):
		if x >= pixel_index - 1:
			if "R" in channels:
				extracted_secret_in_bits.append(r[x][-3:])
			if "G" in channels:
				extracted_secret_in_bits.append(g[x][-3:])
			if "B" in channels:
				extracted_secret_in_bits.append(b[x][-2:])
	return extracted_secret_in_bits

def secret_correctly_encoded(secret_in_chunks, output):
	for x in range(len(secret_in_chunks)):
		#check if the x-th element of the secret injected is equal to the one extracted
		if(secret_in_chunks[x] != output[x]):
			#sometimes it is possible that the secret injected can be something like 
			#['000', '010', '10'], i.e., the last element is different in terms of size w.r.t.
			#the other elements. Thus, the following check deals with this situations.
			if secret_in_chunks[x] != output[x][-len(secret_in_chunks[x]):]:
				return False
	return True

def split_string(stringa, lunghezze):
	lista_divisa = []

	indice_inizio = 0
	while indice_inizio < len(stringa):
		for lunghezza in lunghezze:
			sottostringa = stringa[indice_inizio:indice_inizio + lunghezza]
			lista_divisa.append(sottostringa)
			indice_inizio += lunghezza

	return lista_divisa

settings, args = process_command_line(sys.argv)
r,g,b,a, width, height = parse_image(settings.input)
secret_in_bits = read_secret(settings.secret*100)


'''ENCODE'''

# #CLASSIC LSB
# secret_in_chunks = [secret_in_bits[i:i+settings.bits] for i in range(0, len(secret_in_bits), settings.bits)]
# new_pixels_list = encode_LSB(r,g,b,a, secret_in_chunks, settings.channels, settings.starting_pixel)

#OCEANLOTUS LSB
split_string = split_string(secret_in_bits, [3,3,2])
new_pixels_list = encode_LSB(r,g,b,a, split_string, settings.channels, settings.starting_pixel)

pixels_list_array = np.array(new_pixels_list, dtype=np.uint8)
output_image = Image.fromarray(pixels_list_array)
output_image.save(settings.output)



'''DECODE'''
r,g,b,a, width, height = parse_image(settings.output)

# #CLASSIC LSB
# output = decode_LSB(r,g,b, settings.bits, settings.channels, settings.starting_pixel)
# success = secret_correctly_encoded(secret_in_chunks, output)
# if success:
# 	print("Secret correctly encoded!")
# else:
# 	print("ERROR!")

#OCEANLOTUS LSB
output = decode_OceanLotus_LSB(r,g,b, settings.channels, settings.starting_pixel)
success = secret_correctly_encoded(split_string, output)
if success:
	print("Secret correctly encoded!")
else:
	print("ERROR!")











