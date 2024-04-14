#!/usr/bin/env python3

'''
=========================================
Certificate Verify Tool
=========================================

@version    1
@author     pkiscape.com
@link	    https://github.com/pkiscape


Verifies a given end-entity certificate with its certificate chain, or single issuer.

- Certificate must be in PEM format
- If using a certificate chain, remove the end-entity. Enter the certificate chain with the Root at the bottom.

Example
<Intermediate CA>
<Root CA>

'''

import argparse
import logging
import re
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.backends import default_backend

def load_certificate(certificate, is_file):
	'''
	Loads the PEM or DER certificate into a certificate object. Can load files (is_file=True) or from a string (is_file=False)
	'''

	if is_file:
		try:
			try:
				with open(certificate, "rb") as certificate_file:
					certificate = x509.load_pem_x509_certificate(certificate_file.read(), default_backend())
					return certificate

			except ValueError:
				#Try if it's in DER
				try:
					with open(certificate, "rb") as certificate_file:
						certificate = x509.load_der_x509_certificate(certificate_file.read(), default_backend())
						return certificate

				except Exception as e:
					logging.error(f"Check if your Certificate '{certificate}' is in DER or PEM:\n")
					quit()

		except FileNotFoundError:
			logging.error(f"File {certificate} not found. Please specify a certificate file in PEM or DER")
			quit()

	if not is_file:
		certificate = bytes(certificate,'utf-8')
		certificate = x509.load_pem_x509_certificate(certificate, default_backend())
		return certificate
		
def load_certificate_chain(certificate_chain):
	'''
	
	Loads certificate chain from file.
	Only supports PEM at the moment (determine how to load a der chain?, maybe convert formats?)
	'''
	
	certificate_list = []
	certificate_pem_regex = r'(-----BEGIN CERTIFICATE-----\r?\n.*?-----END CERTIFICATE-----)'

	try:
		with open(certificate_chain, "r") as certificate_chain_file:
			loaded_certificates = certificate_chain_file.read()

		certificate_list = re.findall(certificate_pem_regex, loaded_certificates, re.DOTALL)

		return certificate_list
					
	except FileNotFoundError:
		logging.error(f"File {certificate_chain} not found. Please specify a certificate file in PEM or DER")
		quit()

def get_ski_aki(certificate):

	key_id_list = []

	try:
		sku_value = hex(int.from_bytes(certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest,byteorder='big')).removeprefix('0x').upper()
		key_id_list.append(sku_value)
	except Exception:
		key_id_list.append("No Subject Key Identifier Found")
	
	try:
		aku_value = hex(int.from_bytes(certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier,byteorder='big')).removeprefix('0x').upper()
		key_id_list.append(aku_value)
	except Exception:
		key_id_list.append("No Authority Key Identifier Found")	

	return key_id_list

def verify(end_entity, issuer, mode):
	'''
	Verifies the end entity certificate with the issuer.
	-Checks end-entity certificate with the issuer's public key
	-Checks the Issuer/Subject for further information
	-Returns true or false if verification worked

	OID reference
	Identify the signature type of the end-entity then use issuer's public key to verify

	==RSA==
	RSA_WITH_MD5 = ObjectIdentifier("1.2.840.113549.1.1.4")
    RSA_WITH_SHA1 = ObjectIdentifier("1.2.840.113549.1.1.5")
    _RSA_WITH_SHA1 = ObjectIdentifier("1.3.14.3.2.29")
    RSA_WITH_SHA224 = ObjectIdentifier("1.2.840.113549.1.1.14")
    RSA_WITH_SHA256 = ObjectIdentifier("1.2.840.113549.1.1.11")
    RSA_WITH_SHA384 = ObjectIdentifier("1.2.840.113549.1.1.12")
    RSA_WITH_SHA512 = ObjectIdentifier("1.2.840.113549.1.1.13")

	==ECC==
    ECDSA_WITH_SHA1 = ObjectIdentifier("1.2.840.10045.4.1")
    ECDSA_WITH_SHA224 = ObjectIdentifier("1.2.840.10045.4.3.1")
    ECDSA_WITH_SHA256 = ObjectIdentifier("1.2.840.10045.4.3.2")
    ECDSA_WITH_SHA384 = ObjectIdentifier("1.2.840.10045.4.3.3")
    ECDSA_WITH_SHA512 = ObjectIdentifier("1.2.840.10045.4.3.4")
    https://cryptography.io/en/3.0/_modules/cryptography/x509/oid/
	'''

	rsa_oids = ["1.2.840.113549.1.1.4","1.2.840.113549.1.1.5","1.3.14.3.2.29","1.2.840.113549.1.1.14","1.2.840.113549.1.1.11","1.2.840.113549.1.1.12","1.2.840.113549.1.1.13"]
	ecc_oids = ["1.2.840.10045.4.1","1.2.840.10045.4.3.1","1.2.840.10045.4.3.2","1.2.840.10045.4.3.3","1.2.840.10045.4.3.4"]

	#RSA verification uses the signature, tbs_certificate, padding and signature hash algorithm
	if end_entity.signature_algorithm_oid.dotted_string in rsa_oids:
		try:
			signature_padding = padding.PKCS1v15()

			issuer.public_key().verify(
				signature=end_entity.signature,
				data=end_entity.tbs_certificate_bytes,
				padding=signature_padding,
				algorithm=end_entity.signature_hash_algorithm
				)
			verified = True

		except Exception as rsa_verification_e:
			verified = False

	# ECC uses the signature, tbs_certificate, and hash object based on the signature_hash_algorithm
	if end_entity.signature_algorithm_oid.dotted_string in ecc_oids:

		hash_algorithm = end_entity.signature_hash_algorithm.name.upper()

	 	#Chooses the hash algorithm to use, ECC requires to build a hash object
		if hash_algorithm == "SHA224":
			hash_function_obj = hashes.SHA224()

		if hash_algorithm == "SHA256":
			hash_function_obj = hashes.SHA256()

		if hash_algorithm == "SHA384":
			hash_function_obj = hashes.SHA384()

		if hash_algorithm == "SHA512":
			hash_function_obj = hashes.SHA512()

		if hash_algorithm == "SHA3_224":
			hash_function_obj = hashes.SHA3_224()

		if hash_algorithm == "SHA3_256":
			hash_function_obj = hashes.SHA3_256()

		if hash_algorithm == "SHA3_384":
			hash_function_obj = hashes.SHA3_384()

		if hash_algorithm == "SHA3_512":
			hash_function_obj = hashes.SHA3_512()

		try:
			issuer.public_key().verify(
				signature=end_entity.signature,
				data=end_entity.tbs_certificate_bytes,
				signature_algorithm=ec.ECDSA(hash_function_obj)
				)
			verified = True

		except Exception as ecc_verification_e:
			verified = False

	if mode == "single":
		print(f"Certificate:\n     Subject: {end_entity.subject.rfc4514_string()}\n     Issuer: {end_entity.issuer.rfc4514_string()}")
		end_entity_key_id_list = get_ski_aki(certificate=end_entity)
		print(f"     Subject Key Identifier: {end_entity_key_id_list[0]}\n     Authority Key Identifier: {end_entity_key_id_list[1]}\n")


		print(f"Issuer:\n     Subject: {issuer.subject.rfc4514_string()}\n     Issuer:{issuer.issuer.rfc4514_string()}")
		issuer_key_id_list = get_ski_aki(certificate=issuer)
		print(f"     Subject Key Identifier: {issuer_key_id_list[0]}\n     Authority Key Identifier: {issuer_key_id_list[1]}\n")

	return verified

def certificate_chain_verify_workflow(end_entity,certificate_chain_obj_list):
	
	'''
	verifys the end-entity with the certificate chain
	Uses verify() with some extra logic for multiple certificates
	'''
	# List of verified instances. For each certificate, it will return True or False
	verified_instances = []

	certificate_chain_len = len(certificate_chain_obj_list)

	#Always verify end-entity with first certificate in the list

	end_entity_verified = verify(end_entity=end_entity,issuer=certificate_chain_obj_list[0],mode="chain")
	verified_instances.append(end_entity_verified)

	#End-entity describe
	print(f"0:\n     Subject: {end_entity.subject.rfc4514_string()}\n     Issuer: {end_entity.issuer.rfc4514_string()}")
	end_entity_key_id_list = get_ski_aki(certificate=end_entity)
	print(f"     Subject Key Identifier: {end_entity_key_id_list[0]}\n     Authority Key Identifier: {end_entity_key_id_list[1]}\n")

	if certificate_chain_len > 1:
		for verified_instance in range(certificate_chain_len):
			instance_end_entity = certificate_chain_obj_list[verified_instance]
			print(f"{verified_instance + 1}:\n     Subject: {instance_end_entity.subject.rfc4514_string()}\n     Issuer: {instance_end_entity.issuer.rfc4514_string()}")
			issuer_id_list = get_ski_aki(certificate=instance_end_entity)
			print(f"     Subject Key Identifier: {issuer_id_list[0]}\n     Authority Key Identifier: {issuer_id_list[1]}\n")
				
			try:
				instance_issuer = certificate_chain_obj_list[verified_instance + 1]
				instance_verified = verify(end_entity=instance_end_entity,issuer=instance_issuer,mode="chain")
				verified_instances.append(instance_verified)
				if instance_verified:
					continue

				if (verified_instance+1) == certificate_chain_len:
					break

			except Exception:
				#This is here because at the end of the chain, this is thrown: Error: list index out of range
				pass

		return verified_instances

	else:
		return verified_instances

def main():

	'''
	Main function of the Certificate Verify Tool which handles the main logic. 
	-Loads end-entity certificate
	-Checks validity of end-entity
	-Loads the single issuer or certificate chain
	-Verifies the end-entity certificate with either the certificate chain or single issuer

	'''

	argparse_main = argparse.ArgumentParser(description="X.509 Certificate Verify Tool")
	argparse_main.add_argument("-e","--end-entity",nargs="?",required=True, help="Define your end-entity certificate (PEM/DER) file to verify")
	argparse_main.add_argument("-i","--issuers",nargs="?", required=True,
		help="Define the end-entity's CA certificate issuer(s) file. Accepts a full certificate chain or single issuer file. Must be in PEM")
	argparse_main.add_argument("-v","--verbose",action="store_true", default=False, help="Enable verbosity (more wordiness)")

	args = argparse_main.parse_args()

	print(f"\nWelcome to the Certificate Verify Tool! By: pkiscape.com\n")

	verbose = args.verbose
	end_entity_file = args.end_entity

	#Always load the end-entity certificate
	end_entity = load_certificate(certificate=end_entity_file, is_file=True)

	#Check Validity
	today = datetime.today()
	time_difference = end_entity.not_valid_after - today


	if args.issuers:
		#Determines if there's one or multiple certificates in the file
		try:
			with open(args.issuers, "r") as initial_issuer_file:
				opened_initial_issuer_file = initial_issuer_file.readlines()
		
		except FileNotFoundError:
			logging.error(f"File {args.issuers} not found, please double check the filename.")
			quit()

		certificate_count = 0
		for line in opened_initial_issuer_file:
			if "BEGIN" in line:
				certificate_count = certificate_count + 1
		
		if certificate_count >= 2:
			multiple_issuers = True
		else:
			multiple_issuers = False

	# verify end-entity and single issuer
	if not multiple_issuers:
		issuer_file = args.issuers
		issuer = load_certificate(certificate=issuer_file, is_file=True)
		verified = verify(end_entity=end_entity,issuer=issuer, mode="single")

		if not verified:
			verified_result = "FAILURE"
		else:
			verified_result = "SUCCESS"


	# Verify end-entity and certificate chain
	if multiple_issuers:
		certificate_chain_file = args.issuers
		certificate_chain = load_certificate_chain(certificate_chain_file)
		certificate_chain_obj_list = []
		for certificate in certificate_chain:
			loaded_certificate = load_certificate(certificate,is_file=False)
			certificate_chain_obj_list.append(loaded_certificate)

		chain_verified_instances = certificate_chain_verify_workflow(end_entity=end_entity,certificate_chain_obj_list=certificate_chain_obj_list)

		if False in chain_verified_instances:
			verified_result = "FAILURE"

		else:
			verified_result = "SUCCESS"

	#Print out the results		
	print("==========Results==========\n")
	print(f"verified Result: {verified_result}")

	if time_difference.days < 30:
		if time_difference.days < -1:
			print(f"Warning: {end_entity_file} is expired. Expiration date: {end_entity.not_valid_after} ")
		else:
			print(f"Warning: {end_entity_file} is going to expire in {time_difference}")

	if not multiple_issuers:
		if verified:
			print(f"{end_entity_file}'s signature successfully verified with {issuer_file}'s public key")

		if not verified:
			print(f"{end_entity_file} was not issued by {issuer_file}")
	else:
		if verified_result == "SUCCESS":
			print(f"{end_entity_file}'s signature successfully verified with each certificate's public key in {certificate_chain_file}")
			if verbose:
				print("\nAdditional Information:")
				for ca_cert, ca_cert_result in enumerate(chain_verified_instances):
					print(f"    Certificate:{ca_cert} verified by Certificate:{ca_cert+1}")

		else:
			print(f"{end_entity_file} was not issued by {certificate_chain_file}")
			if verbose:
				print("\nAdditional Information:")
				for ca_cert, ca_cert_result in enumerate(chain_verified_instances):
					if ca_cert_result:
						print(f"    Certificate: {ca_cert} verified by Certificate: {ca_cert+1}")
					else:
						print(f"    Certificate: {ca_cert} was not issued by Certificate: {ca_cert+1}")

	print()

if __name__ == '__main__':
	main()
