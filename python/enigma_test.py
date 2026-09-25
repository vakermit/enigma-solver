#!/usr/bin/env python3

from enigma.machine import EnigmaMachine

# setup machine according to specs from a daily key sheet:

machine = EnigmaMachine.from_key_sheet(
    rotors="I II III",
    reflector="B",
    ring_settings=[1, 1, 1],
    plugboard_settings="TU AL DF ER GH NO PQ SV WX YZ",
)

# machine = EnigmaMachine.from_key_sheet(
#        rotors='II IV V',
#        reflector='B',
#        ring_settings=[1, 20, 11],
#        plugboard_settings='AV BS CG DL FU HZ IN KM OW RX')

# set machine initial starting position
machine.set_display("AAA")

# # decrypt the message key
# msg_key = machine.process_text('KCH')

# # decrypt the cipher text with the unencrypted message key
# machine.set_display(msg_key)

ciphertext = "YPTFZ FZULI TAABH ZMYBC COJPC CODJC NJKBE MWTZ"
plaintext = machine.process_text(ciphertext)

print(plaintext)
