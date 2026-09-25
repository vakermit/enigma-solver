#!/usr/bin/env python3

from enigma.machine import EnigmaMachine

# setup machine according to specs from a daily key sheet:

codetext='TPGLT WOGGJ MATQQ XFADA QACOA KWWVB NKXCK XCYDN VSSGQ CMJZW VQABZ I'

machine = EnigmaMachine.from_key_sheet(
       rotors='I II III',
       reflector='B',
       ring_settings=[0,0,0],
       plugboard_settings='TU AL DF ER GH NO PQ SV WX YZ')
       # plugboard_settings='AV BS CG DL FU HZ IN KM OW RX')

print(machine)

# engine = enigma.Enigma(rotor.ROTOR_Reflector_A, rotor.ROTOR_I,
#                                 rotor.ROTOR_II, rotor.ROTOR_III, key="ABC",
#                                 plugs="AV BS CG DL FU HZ IN KM OW RX")

# # set machine initial starting position
machine.set_display('AAA')

# # decrypt the message key
decoded = machine.process_text(codetext)

print(decoded)

# # decrypt the cipher text with the unencrypted message key
# machine.set_display(msg_key)

# ciphertext = 'NIBLFMYMLLUFWCASCSSNVHAZ'
# plaintext = machine.process_text(ciphertext)

# print(plaintext)

# for plug_count in range(11):


# from itertools import combinations
# import string

# for b in combinations(string.ascii_uppercase,4):
#        print(''.join(b))

