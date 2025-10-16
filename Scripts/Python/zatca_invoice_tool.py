# -*- coding: utf-8 -*-
"""
ZATCA (Saudi Arabia) UBL 2.1 Invoice Toolkit.

This script functions as a command-line tool inspired by the ZATCA Java SDK,
providing a suite of functions for generating, hashing, validating, and preparing
ZATCA-compliant e-invoices for API submission.

Prerequisites:
1. Install required libraries: pip install cryptography lxml
2. For signing: Run `generate_keys.py` to create 'ec-private-key.pem' and 'certificate.pem'.
3. For CSR generation: Run `generate_keys.py csr ...`.

Usage Examples:
  # 1. Generate a template CSR config file
  python zatca_invoice_tool.py generate-csr-config --output csr-config-example-EN.properties

  # 2. Generate a signed invoice from JSON data
  python zatca_invoice_tool.py generate --input invoice_details.json --output signed_invoice.xml

  # 3. Generate using an external hasher that's in the system PATH
  python zatca_invoice_tool.py generate --input invoice_details.json --output signed_invoice.xml --external-hasher fatoora

  # 4. Validate a signed invoice XML for well-formedness
  python zatca_invoice_tool.py validate --invoice signed_invoice.xml

  # 5. Generate the JSON request for the Compliance API
  python zatca_invoice_tool.py generate-api-request --invoice signed_invoice.xml --output api_request.json

  # 6. Calculate the hash of an unsigned invoice
  python zatca_invoice_tool.py generate-hash --input invoice_details.json
"""
import base64
import hashlib
import json
import argparse
import subprocess
import re
import tempfile
import os
import copy
from lxml import etree as ET
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_pem_x509_certificate

# --- Helper Functions ---

def to_saudi_time(dt):
    """Converts a datetime object to ZATCA's required format (YYYY-MM-DDTHH:MM:SSZ)."""
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')

def tlv_encode(tag, value):
    """Encodes a single Tag-Length-Value field for the QR code."""
    tag_bytes = tag.to_bytes(1, 'big')
    value_bytes = value.encode('utf-8')
    len_bytes = len(value_bytes).to_bytes(1, 'big')
    return tag_bytes + len_bytes + value_bytes

def generate_qr_code_data(seller_name, vat_number, timestamp, invoice_total, vat_total, xml_hash, signature, public_key, certificate_signature):
    """Generates the Base64 encoded TLV string for the QR code."""
    tlv_string = b''
    tlv_string += tlv_encode(1, seller_name)
    tlv_string += tlv_encode(2, vat_number)
    tlv_string += tlv_encode(3, timestamp)
    tlv_string += tlv_encode(4, str(invoice_total))
    tlv_string += tlv_encode(5, str(vat_total))
    tlv_string += tlv_encode(6, xml_hash)
    tlv_string += tlv_encode(7, signature)
    return base64.b64encode(tlv_string).decode('utf-8')

# --- Main Generator Class ---

class ZatcaInvoice:
    """A class to handle ZATCA e-invoice generation, signing, and preparation."""
    def __init__(self, invoice_data=None, private_key_path="ec-private-key.pem", cert_path="certificate.pem"):
        self.invoice_data = invoice_data
        self.private_key_path = private_key_path
        self.cert_path = cert_path
        self.private_key = None
        self.certificate = None
        self.namespaces = {
            None: 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2',
            'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
            'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2',
            'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
            'ds': 'http://www.w3.org/2000/09/xmldsig#',
            'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
            'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
            'sbc': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2',
            'xades': 'http://uri.etsi.org/01903/v1.3.2#'
        }

    def _get_tag(self, prefix, tag_name):
        return f"{{{self.namespaces[prefix]}}}{tag_name}"

    def _load_credentials(self):
        with open(self.private_key_path, "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(key_file.read(), password=None)
        with open(self.cert_path, "rb") as cert_file:
            self.certificate = load_pem_x509_certificate(cert_file.read())

    def _build_invoice_xml_structure(self):
        """Builds the main invoice XML structure without signature or QR."""
        if not self.invoice_data:
            raise ValueError("Invoice data is required to build the XML structure.")

        invoice = ET.Element(self._get_tag(None, 'Invoice'), nsmap=self.namespaces)
        ubl_extensions = ET.SubElement(invoice, self._get_tag('ext', 'UBLExtensions'))
        
        ET.SubElement(invoice, self._get_tag('cbc', 'ProfileID')).text = 'reporting:1.0'
        ET.SubElement(invoice, self._get_tag('cbc', 'ID')).text = self.invoice_data['id']
        ET.SubElement(invoice, self._get_tag('cbc', 'UUID')).text = self.invoice_data['uuid']
        ET.SubElement(invoice, self._get_tag('cbc', 'IssueDate')).text = self.invoice_data['issue_date']
        ET.SubElement(invoice, self._get_tag('cbc', 'IssueTime')).text = self.invoice_data['issue_time']
        ET.SubElement(invoice, self._get_tag('cbc', 'InvoiceTypeCode'), name="0100000").text = '388'
        ET.SubElement(invoice, self._get_tag('cbc', 'DocumentCurrencyCode')).text = 'SAR'
        ET.SubElement(invoice, self._get_tag('cbc', 'TaxCurrencyCode')).text = 'SAR'
        
        icv_ref = ET.SubElement(invoice, self._get_tag('cac', 'AdditionalDocumentReference'))
        ET.SubElement(icv_ref, self._get_tag('cbc', 'ID')).text = 'ICV'
        ET.SubElement(icv_ref, self._get_tag('cbc', 'UUID')).text = self.invoice_data['icv']

        pih_ref = ET.SubElement(invoice, self._get_tag('cac', 'AdditionalDocumentReference'))
        ET.SubElement(pih_ref, self._get_tag('cbc', 'ID')).text = 'PIH'
        pih_attachment = ET.SubElement(pih_ref, self._get_tag('cac', 'Attachment'))
        ET.SubElement(pih_attachment, self._get_tag('cbc', 'EmbeddedDocumentBinaryObject'), mimeCode="text/plain").text = self.invoice_data['previous_invoice_hash']

        qr_ref = ET.SubElement(invoice, self._get_tag('cac', 'AdditionalDocumentReference'))
        ET.SubElement(qr_ref, self._get_tag('cbc', 'ID')).text = 'QR'
        qr_attachment = ET.SubElement(qr_ref, self._get_tag('cac', 'Attachment'))
        self.qr_code_element = ET.SubElement(qr_attachment, self._get_tag('cbc', 'EmbeddedDocumentBinaryObject'), mimeCode="text/plain")
        
        signature_cac = ET.SubElement(invoice, self._get_tag('cac', 'Signature'))
        ET.SubElement(signature_cac, self._get_tag('cbc', 'ID')).text = 'urn:oasis:names:specification:ubl:signature:Invoice'
        ET.SubElement(signature_cac, self._get_tag('cbc', 'SignatureMethod')).text = 'urn:oasis:names:specification:ubl:dsig:enveloped:xades'

        self._add_parties(invoice)
        self._add_delivery_and_payment(invoice)
        self._add_allowance(invoice)
        self._add_totals(invoice)
        self._add_invoice_lines(invoice)
        
        return invoice, ubl_extensions

    def _add_parties(self, parent):
        seller = self.invoice_data['seller']
        customer = self.invoice_data['customer']
        
        # Supplier Party
        supplier_party = ET.SubElement(parent, self._get_tag('cac', 'AccountingSupplierParty'))
        party = ET.SubElement(supplier_party, self._get_tag('cac', 'Party'))
        ET.SubElement(ET.SubElement(party, self._get_tag('cac', 'PartyIdentification')), self._get_tag('cbc', 'ID'), schemeID='CRN').text = seller['crn']
        postal_address = ET.SubElement(party, self._get_tag('cac', 'PostalAddress'))
        ET.SubElement(postal_address, self._get_tag('cbc', 'StreetName')).text = seller['street']
        ET.SubElement(postal_address, self._get_tag('cbc', 'BuildingNumber')).text = seller['building_number']
        ET.SubElement(postal_address, self._get_tag('cbc', 'CitySubdivisionName')).text = seller['district']
        ET.SubElement(postal_address, self._get_tag('cbc', 'CityName')).text = seller['city']
        ET.SubElement(postal_address, self._get_tag('cbc', 'PostalZone')).text = seller['postal_code']
        ET.SubElement(ET.SubElement(postal_address, self._get_tag('cac', 'Country')), self._get_tag('cbc', 'IdentificationCode')).text = 'SA'
        party_tax_scheme = ET.SubElement(party, self._get_tag('cac', 'PartyTaxScheme'))
        ET.SubElement(party_tax_scheme, self._get_tag('cbc', 'CompanyID')).text = seller['vat_number']
        ET.SubElement(ET.SubElement(party_tax_scheme, self._get_tag('cac', 'TaxScheme')), self._get_tag('cbc', 'ID')).text = 'VAT'
        ET.SubElement(ET.SubElement(party, self._get_tag('cac', 'PartyLegalEntity')), self._get_tag('cbc', 'RegistrationName')).text = seller['name']

        # Customer Party
        customer_party = ET.SubElement(parent, self._get_tag('cac', 'AccountingCustomerParty'))
        party_cust = ET.SubElement(customer_party, self._get_tag('cac', 'Party'))
        postal_address_cust = ET.SubElement(party_cust, self._get_tag('cac', 'PostalAddress'))
        ET.SubElement(postal_address_cust, self._get_tag('cbc', 'StreetName')).text = customer['street']
        ET.SubElement(postal_address_cust, self._get_tag('cbc', 'BuildingNumber')).text = customer['building_number']
        ET.SubElement(postal_address_cust, self._get_tag('cbc', 'CitySubdivisionName')).text = customer['district']
        ET.SubElement(postal_address_cust, self._get_tag('cbc', 'CityName')).text = customer['city']
        ET.SubElement(postal_address_cust, self._get_tag('cbc', 'PostalZone')).text = customer['postal_code']
        ET.SubElement(ET.SubElement(postal_address_cust, self._get_tag('cac', 'Country')), self._get_tag('cbc', 'IdentificationCode')).text = 'SA'
        party_tax_scheme_cust = ET.SubElement(party_cust, self._get_tag('cac', 'PartyTaxScheme'))
        ET.SubElement(party_tax_scheme_cust, self._get_tag('cbc', 'CompanyID')).text = customer['vat_number']
        ET.SubElement(ET.SubElement(party_tax_scheme_cust, self._get_tag('cac', 'TaxScheme')), self._get_tag('cbc', 'ID')).text = 'VAT'
        ET.SubElement(ET.SubElement(party_cust, self._get_tag('cac', 'PartyLegalEntity')), self._get_tag('cbc', 'RegistrationName')).text = customer['name']

    def _add_delivery_and_payment(self, parent):
        delivery = ET.SubElement(parent, self._get_tag('cac', 'Delivery'))
        ET.SubElement(delivery, self._get_tag('cbc', 'ActualDeliveryDate')).text = self.invoice_data['supply_date']
        payment_means = ET.SubElement(parent, self._get_tag('cac', 'PaymentMeans'))
        ET.SubElement(payment_means, self._get_tag('cbc', 'PaymentMeansCode')).text = '10'

    def _add_allowance(self, parent):
        allowance_charge = ET.SubElement(parent, self._get_tag('cac', 'AllowanceCharge'))
        ET.SubElement(allowance_charge, self._get_tag('cbc', 'ChargeIndicator')).text = 'false'
        ET.SubElement(allowance_charge, self._get_tag('cbc', 'AllowanceChargeReason')).text = 'discount'
        ET.SubElement(allowance_charge, self._get_tag('cbc', 'Amount'), currencyID='SAR').text = '0.00'
        tax_category_allowance = ET.SubElement(allowance_charge, self._get_tag('cac', 'TaxCategory'))
        ET.SubElement(tax_category_allowance, self._get_tag('cbc', 'ID'), schemeID="UN/ECE 5305", schemeAgencyID="6").text = 'S'
        ET.SubElement(tax_category_allowance, self._get_tag('cbc', 'Percent')).text = '15.00'
        ET.SubElement(ET.SubElement(tax_category_allowance, self._get_tag('cac', 'TaxScheme')), self._get_tag('cbc', 'ID'), schemeID="UN/ECE 5153", schemeAgencyID="6").text = 'VAT'
        
    def _add_totals(self, parent):
        totals = self.invoice_data['totals']
        ET.SubElement(ET.SubElement(parent, self._get_tag('cac', 'TaxTotal')), self._get_tag('cbc', 'TaxAmount'), currencyID='SAR').text = f"{totals['vat']:.2f}"
        
        tax_total_details = ET.SubElement(parent, self._get_tag('cac', 'TaxTotal'))
        ET.SubElement(tax_total_details, self._get_tag('cbc', 'TaxAmount'), currencyID='SAR').text = f"{totals['vat']:.2f}"
        tax_subtotal = ET.SubElement(tax_total_details, self._get_tag('cac', 'TaxSubtotal'))
        ET.SubElement(tax_subtotal, self._get_tag('cbc', 'TaxableAmount'), currencyID='SAR').text = f"{totals['subtotal']:.2f}"
        ET.SubElement(tax_subtotal, self._get_tag('cbc', 'TaxAmount'), currencyID='SAR').text = f"{totals['vat']:.2f}"
        tax_category = ET.SubElement(tax_subtotal, self._get_tag('cac', 'TaxCategory'))
        ET.SubElement(tax_category, self._get_tag('cbc', 'ID'), schemeID="UN/ECE 5305", schemeAgencyID="6").text = 'S'
        ET.SubElement(tax_category, self._get_tag('cbc', 'Percent')).text = '15.00'
        ET.SubElement(ET.SubElement(tax_category, self._get_tag('cac', 'TaxScheme')), self._get_tag('cbc', 'ID'), schemeID="UN/ECE 5153", schemeAgencyID="6").text = 'VAT'

        legal_monetary_total = ET.SubElement(parent, self._get_tag('cac', 'LegalMonetaryTotal'))
        ET.SubElement(legal_monetary_total, self._get_tag('cbc', 'LineExtensionAmount'), currencyID='SAR').text = f"{totals['subtotal']:.2f}"
        ET.SubElement(legal_monetary_total, self._get_tag('cbc', 'TaxExclusiveAmount'), currencyID='SAR').text = f"{totals['subtotal']:.2f}"
        ET.SubElement(legal_monetary_total, self._get_tag('cbc', 'TaxInclusiveAmount'), currencyID='SAR').text = f"{totals['total']:.2f}"
        ET.SubElement(legal_monetary_total, self._get_tag('cbc', 'AllowanceTotalAmount'), currencyID='SAR').text = '0.00'
        ET.SubElement(legal_monetary_total, self._get_tag('cbc', 'PrepaidAmount'), currencyID='SAR').text = '0.00'
        ET.SubElement(legal_monetary_total, self._get_tag('cbc', 'PayableAmount'), currencyID='SAR').text = f"{totals['total']:.2f}"

    def _add_invoice_lines(self, parent):
        for i, item in enumerate(self.invoice_data['items']):
            line = ET.SubElement(parent, self._get_tag('cac', 'InvoiceLine'))
            ET.SubElement(line, self._get_tag('cbc', 'ID')).text = str(i + 1)
            ET.SubElement(line, self._get_tag('cbc', 'InvoicedQuantity'), unitCode='PCE').text = f"{item['quantity']:.6f}"
            ET.SubElement(line, self._get_tag('cbc', 'LineExtensionAmount'), currencyID='SAR').text = f"{item['net_price']:.2f}"
            
            line_tax_total = ET.SubElement(line, self._get_tag('cac', 'TaxTotal'))
            ET.SubElement(line_tax_total, self._get_tag('cbc', 'TaxAmount'), currencyID='SAR').text = f"{item['vat_amount']:.2f}"
            ET.SubElement(line_tax_total, self._get_tag('cbc', 'RoundingAmount'), currencyID='SAR').text = f"{item['total_inclusive']:.2f}"

            item_elem = ET.SubElement(line, self._get_tag('cac', 'Item'))
            ET.SubElement(item_elem, self._get_tag('cbc', 'Name')).text = item['name']
            classified_tax_category = ET.SubElement(item_elem, self._get_tag('cac', 'ClassifiedTaxCategory'))
            ET.SubElement(classified_tax_category, self._get_tag('cbc', 'ID')).text = 'S'
            ET.SubElement(classified_tax_category, self._get_tag('cbc', 'Percent')).text = '15.00'
            ET.SubElement(ET.SubElement(classified_tax_category, self._get_tag('cac', 'TaxScheme')), self._get_tag('cbc', 'ID')).text = 'VAT'
            ET.SubElement(ET.SubElement(line, self._get_tag('cac', 'Price')), self._get_tag('cbc', 'PriceAmount'), currencyID='SAR').text = f"{item['price']:.2f}"
    
    def get_invoice_hash(self):
        invoice_element, ubl_extensions = self._build_invoice_xml_structure()
        
        # Per ZATCA spec (BR-KSA-26), remove specific elements before hashing
        invoice_element.remove(ubl_extensions)
        
        signature_placeholder = invoice_element.find('.//cac:Signature', self.namespaces)
        if signature_placeholder is not None:
            signature_placeholder.getparent().remove(signature_placeholder)
        
        qr_ref = invoice_element.find(".//cac:AdditionalDocumentReference[cbc:ID='QR']", self.namespaces)
        if qr_ref is not None:
            qr_ref.getparent().remove(qr_ref)

        invoice_xml_str_c14n = ET.tostring(invoice_element, method='c14n', exclusive=True)
        return base64.b64encode(hashlib.sha256(invoice_xml_str_c14n).digest()).decode('utf-8')

    def generate_signed_invoice(self, external_hasher_cmd=None, output_path=None):
        """
        Generates the final signed invoice XML.
        
        If an external_hasher_cmd is provided, it will write the file directly to the
        output_path and return None. Otherwise, it returns the XML as a string.
        """
        self._load_credentials()
        invoice_element, ubl_extensions = self._build_invoice_xml_structure()

        if external_hasher_cmd:
            if not output_path:
                raise ValueError("Output path is required when using an external hasher.")

            # Define a separate path for the intermediate file used for hashing
            output_dir = os.path.dirname(output_path)
            output_filename = os.path.basename(output_path)
            base, ext = os.path.splitext(output_filename)
            hashing_file_path = os.path.join(output_dir, f"{base}_for_hashing{ext}")

            try:
                # --- PASS 1: Generate a structurally complete invoice with a dummy hash ---
                print(f"[INFO] Pass 1: Generating intermediate signed invoice for hashing at '{hashing_file_path}'.")
                dummy_hash = "DUMMY_INVOICE_HASH_PLACEHOLDER"
                self._build_signature_block(ubl_extensions, dummy_hash)

                # Write the structurally complete but incorrectly signed file to the hashing path
                invoice_for_hashing_str = ET.tostring(invoice_element, pretty_print=True, xml_declaration=True, encoding='UTF-8').decode('utf-8')
                with open(hashing_file_path, "w", encoding="utf-8") as f:
                    f.write(invoice_for_hashing_str)
                
                # --- Run the external hasher ---
                print(f"[INFO] Running external tool: '{external_hasher_cmd}' on file '{hashing_file_path}'")
                command_str = f'{external_hasher_cmd} -generateHash -invoice "{hashing_file_path}"'
                
                result = subprocess.run(command_str, capture_output=True, text=True, check=False, encoding='utf-8', shell=True)

                if result.returncode != 0:
                    raise subprocess.CalledProcessError(result.returncode, command_str, output=result.stdout, stderr=result.stderr)
                
                match = re.search(r"INVOICE HASH\s*=\s*(\S+)", result.stdout)
                if not match:
                    raise RuntimeError(f"Could not find 'INVOICE HASH' in the output of the external tool.\nOutput:\n{result.stdout}")
                
                real_hash = match.group(1).strip()
                print(f"[SUCCESS] Retrieved invoice hash from external tool: {real_hash}")

                # --- PASS 2: Patch and re-sign the in-memory XML with the real hash ---
                print("[INFO] Pass 2: Re-signing invoice with the correct hash.")
                
                # 1. Update invoice hash digest in the main XML tree
                invoice_digest_elem = invoice_element.find(".//ds:Reference[@Id='invoiceSignedData']/ds:DigestValue", self.namespaces)
                invoice_digest_elem.text = real_hash

                # 2. Re-calculate SignedInfo digest and re-sign to get a new SignatureValue
                signed_info = invoice_element.find('.//ds:SignedInfo', self.namespaces)
                signed_info_c14n = ET.tostring(signed_info, method='c14n', exclusive=True)
                new_signature_digest = self.private_key.sign(signed_info_c14n, ec.ECDSA(hashes.SHA256()))
                new_signature_b64 = base64.b64encode(new_signature_digest).decode('utf-8')

                # 3. Update SignatureValue in the XML tree
                sig_value_elem = invoice_element.find('.//ds:SignatureValue', self.namespaces)
                sig_value_elem.text = new_signature_b64

                # 4. Update QR code with the real hash and new signature
                self.qr_code_element.text = generate_qr_code_data(
                    seller_name=self.invoice_data['seller']['name'],
                    vat_number=self.invoice_data['seller']['vat_number'],
                    timestamp=to_saudi_time(datetime.now(timezone.utc)),
                    invoice_total=f"{self.invoice_data['totals']['total']:.2f}",
                    vat_total=f"{self.invoice_data['totals']['vat']:.2f}",
                    xml_hash=real_hash,
                    signature=new_signature_b64,
                    public_key=base64.b64encode(self.private_key.public_key().public_bytes(
                        encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint
                    )).decode('utf-8'),
                    certificate_signature=base64.b64encode(self.certificate.signature).decode('utf-8')
                )

                # 5. Serialize and save the final, correct XML to the original output_path
                final_xml_string = ET.tostring(invoice_element, pretty_print=True, xml_declaration=True, encoding='UTF-8').decode('utf-8')
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(final_xml_string)
                
                print(f"[INFO] The intermediate file used for hashing has been saved as: '{hashing_file_path}'")
                return None # Signal that writing is complete

            except Exception as e:
                # On error, clean up the intermediate file for hashing.
                if os.path.exists(hashing_file_path):
                    os.remove(hashing_file_path)
                if isinstance(e, FileNotFoundError):
                    print(f"[ERROR] External hasher command not found: '{external_hasher_cmd}'. Please ensure it is in your system's PATH.")
                elif isinstance(e, subprocess.CalledProcessError):
                     print(f"[ERROR] External hasher failed with exit code {e.returncode}.")
                     print(f"STDOUT:\n{e.output}")
                     print(f"STDERR:\n{e.stderr}")
                raise e

        else:
            # --- Original single-pass process for internal hasher ---
            invoice_element_for_hash = copy.deepcopy(invoice_element)
            ubl_ext_element = invoice_element_for_hash.find('.//ext:UBLExtensions', self.namespaces)
            if ubl_ext_element is not None: ubl_ext_element.getparent().remove(ubl_ext_element)
            qr_ref = invoice_element_for_hash.find(".//cac:AdditionalDocumentReference[cbc:ID='QR']", self.namespaces)
            if qr_ref is not None: qr_ref.getparent().remove(qr_ref)
            sig_placeholder = invoice_element_for_hash.find('.//cac:Signature', self.namespaces)
            if sig_placeholder is not None: sig_placeholder.getparent().remove(sig_placeholder)
            
            invoice_xml_str_c14n = ET.tostring(invoice_element_for_hash, method='c14n', exclusive=True)
            invoice_hash_b64 = base64.b64encode(hashlib.sha256(invoice_xml_str_c14n).digest()).decode('utf-8')

            self._build_signature_block(ubl_extensions, invoice_hash_b64)
            return ET.tostring(invoice_element, pretty_print=True, xml_declaration=True, encoding='UTF-8').decode('utf-8')

    def _build_signature_block(self, ubl_extensions, invoice_hash_b64):
        # Clear any existing signature extensions to ensure a clean build
        for ext in ubl_extensions.findall('ext:UBLExtension', self.namespaces):
            ubl_extensions.remove(ext)

        sig_extension = ET.SubElement(ubl_extensions, self._get_tag('ext', 'UBLExtension'))
        ET.SubElement(sig_extension, self._get_tag('ext', 'ExtensionURI')).text = 'urn:oasis:names:specification:ubl:dsig:enveloped:xades'
        ext_content = ET.SubElement(sig_extension, self._get_tag('ext', 'ExtensionContent'))
        
        ubl_doc_signatures = ET.SubElement(ext_content, self._get_tag('sig', 'UBLDocumentSignatures'))
        sig_info = ET.SubElement(ubl_doc_signatures, self._get_tag('sac', 'SignatureInformation'))
        ET.SubElement(sig_info, self._get_tag('cbc', 'ID')).text = 'urn:oasis:names:specification:ubl:signature:1'
        ET.SubElement(sig_info, self._get_tag('sbc', 'ReferencedSignatureID')).text = 'urn:oasis:names:specification:ubl:signature:Invoice'
        
        signature_block = ET.SubElement(sig_info, self._get_tag('ds', 'Signature'), Id='signature')
        signed_info = ET.SubElement(signature_block, self._get_tag('ds', 'SignedInfo'))
        ET.SubElement(signed_info, self._get_tag('ds', 'CanonicalizationMethod'), Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#')
        ET.SubElement(signed_info, self._get_tag('ds', 'SignatureMethod'), Algorithm='http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256')
        
        ref_invoice = ET.SubElement(signed_info, self._get_tag('ds', 'Reference'), Id='invoiceSignedData', URI='')
        ET.SubElement(ET.SubElement(ref_invoice, self._get_tag('ds', 'Transforms')), self._get_tag('ds', 'Transform'), Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature')
        ET.SubElement(ref_invoice, self._get_tag('ds', 'DigestMethod'), Algorithm='http://www.w3.org/2001/04/xmlenc#sha256')
        ET.SubElement(ref_invoice, self._get_tag('ds', 'DigestValue')).text = invoice_hash_b64
        
        xades_props_digest_b64, signed_props_element = self._build_xades_properties()

        ref_props = ET.SubElement(signed_info, self._get_tag('ds', 'Reference'), Type='http://uri.etsi.org/01903/v1.3.2#SignedProperties', URI='#xadesSignedProperties')
        ET.SubElement(ref_props, self._get_tag('ds', 'DigestMethod'), Algorithm='http://www.w3.org/2001/04/xmlenc#sha256')
        ET.SubElement(ref_props, self._get_tag('ds', 'DigestValue')).text = xades_props_digest_b64

        signed_info_c14n = ET.tostring(signed_info, method='c14n', exclusive=True)
        signature_digest = self.private_key.sign(signed_info_c14n, ec.ECDSA(hashes.SHA256()))
        signature_b64 = base64.b64encode(signature_digest).decode('utf-8')
        ET.SubElement(signature_block, self._get_tag('ds', 'SignatureValue')).text = signature_b64

        cert_der = self.certificate.public_bytes(serialization.Encoding.DER)
        key_info = ET.SubElement(signature_block, self._get_tag('ds', 'KeyInfo'))
        x509_data = ET.SubElement(key_info, self._get_tag('ds', 'X509Data'))
        ET.SubElement(x509_data, self._get_tag('ds', 'X509Certificate')).text = base64.b64encode(cert_der).decode('utf-8')

        ds_object = ET.SubElement(signature_block, self._get_tag('ds', 'Object'))
        ds_object.append(signed_props_element)

        self.qr_code_element.text = generate_qr_code_data(
            seller_name=self.invoice_data['seller']['name'],
            vat_number=self.invoice_data['seller']['vat_number'],
            timestamp=to_saudi_time(datetime.now(timezone.utc)),
            invoice_total=f"{self.invoice_data['totals']['total']:.2f}",
            vat_total=f"{self.invoice_data['totals']['vat']:.2f}",
            xml_hash=invoice_hash_b64,
            signature=signature_b64,
            public_key=base64.b64encode(self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint
            )).decode('utf-8'),
            certificate_signature=base64.b64encode(self.certificate.signature).decode('utf-8')
        )

    def _build_xades_properties(self):
        qualifying_props = ET.Element(self._get_tag('xades', 'QualifyingProperties'), Target='#signature')
        signed_props = ET.SubElement(qualifying_props, self._get_tag('xades', 'SignedProperties'), Id='xadesSignedProperties')
        signed_sig_props = ET.SubElement(signed_props, self._get_tag('xades', 'SignedSignatureProperties'))
        
        ET.SubElement(signed_sig_props, self._get_tag('xades', 'SigningTime')).text = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
        
        signing_cert = ET.SubElement(signed_sig_props, self._get_tag('xades', 'SigningCertificate'))
        cert = ET.SubElement(signing_cert, self._get_tag('xades', 'Cert'))
        cert_digest = ET.SubElement(cert, self._get_tag('xades', 'CertDigest'))
        ET.SubElement(cert_digest, self._get_tag('ds', 'DigestMethod'), Algorithm='http://www.w3.org/2001/04/xmlenc#sha256')
        
        cert_der = self.certificate.public_bytes(serialization.Encoding.DER)
        cert_hash_b64 = base64.b64encode(hashlib.sha256(cert_der).digest()).decode('utf-8')
        ET.SubElement(cert_digest, self._get_tag('ds', 'DigestValue')).text = cert_hash_b64
        
        issuer_serial = ET.SubElement(cert, self._get_tag('xades', 'IssuerSerial'))
        ET.SubElement(issuer_serial, self._get_tag('ds', 'X509IssuerName')).text = self.certificate.issuer.rfc4514_string()
        ET.SubElement(issuer_serial, self._get_tag('ds', 'X509SerialNumber')).text = str(self.certificate.serial_number)

        props_c14n = ET.tostring(signed_props, method='c14n', exclusive=True)
        props_digest = base64.b64encode(hashlib.sha256(props_c14n).digest()).decode('utf-8')

        return props_digest, qualifying_props

# --- Command-Line Functions ---

def generate_csr_config(output_path):
    """Generates a template csr.ini configuration file."""
    config_template = """# ZATCA CSR (Certificate Signing Request) Configuration
# This file contains the details required to generate a CSR for ZATCA e-invoicing.
# The 'organization_identifier' is typically your VAT Registration Number.
# The 'serial_number' has a specific format required by ZATCA.
[csr_details]
common_name = TST-886431145-399999999900003
serial_number = 1-TST|2-TST|3-ed22f1d8-e6a2-1118-9b58-d9a8f11e445f
organization_identifier = 399999999900003
organization_unit_name = Riyadh Branch
organization_name = Maximum Speed Tech Supply LTD
country_name = SA
invoice_type = 1100
location_address = RRRD2929
industry_business_category = Supply activities
"""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(config_template)
    print(f"Successfully generated CSR config template: '{output_path}'")

def validate_invoice(invoice_path):
    """Performs a basic well-formedness check on an invoice XML."""
    print(f"--- Validating '{invoice_path}' ---")
    try:
        parser = ET.XMLParser(resolve_entities=False)
        ET.parse(invoice_path, parser)
        print("[SUCCESS] The XML is well-formed.")
        print("\n[INFO] For full ZATCA compliance, you must validate against the official ZATCA UBL schemas.")
        print("This requires the .xsd files from ZATCA. This tool only checks for XML syntax correctness.")
    except ET.XMLSyntaxError as e:
        print(f"[ERROR] The XML is not well-formed. Details:\n{e}")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred during validation: {e}")

def generate_api_request(invoice_path, output_path):
    """Generates a JSON payload for the ZATCA compliance API."""
    try:
        with open(invoice_path, 'rb') as f:
            xml_bytes = f.read()
        
        # Base64 encode the entire signed XML file content
        invoice_b64 = base64.b64encode(xml_bytes).decode('utf-8')

        # Parse the XML to find the UUID and Invoice Hash
        root = ET.fromstring(xml_bytes)
        namespaces = {k if k is not None else 'def': v for k, v in root.nsmap.items()}
        
        uuid = root.find('.//cbc:UUID', namespaces).text
        
        # The invoice hash is the digest value of the reference to the invoice data
        ref_xpath = ".//ds:Reference[@Id='invoiceSignedData']/ds:DigestValue"
        invoice_hash = root.find(ref_xpath, namespaces).text

        api_payload = {
            "invoiceHash": invoice_hash,
            "uuid": uuid,
            "invoice": invoice_b64
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(api_payload, f, indent=4)
        
        print(f"Successfully generated API request JSON: '{output_path}'")

    except FileNotFoundError:
        print(f"[ERROR] Invoice file not found at '{invoice_path}'")
    except AttributeError:
        print("[ERROR] Could not find UUID or Invoice Hash in the XML. Is the file a correctly signed ZATCA invoice?")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")


# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(description="ZATCA E-Invoice Toolkit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Command: generate-csr-config
    csr_cfg_parser = subparsers.add_parser("generate-csr-config", help="Generate a template CSR configuration file.")
    csr_cfg_parser.add_argument("--output", required=True, help="Path for the output config file (e.g., csr-config.ini).")

    # Command: generate
    gen_parser = subparsers.add_parser("generate", help="Generate a complete, signed ZATCA invoice XML.")
    gen_parser.add_argument("--input", required=True, help="Path to the invoice data JSON file.")
    gen_parser.add_argument("--output", required=True, help="Path for the output signed XML file.")
    gen_parser.add_argument("--key", default="ec-private-key.pem", help="Path to the EC private key PEM file.")
    gen_parser.add_argument("--cert", default="certificate.pem", help="Path to the certificate PEM file.")
    gen_parser.add_argument("--external-hasher", help="[Optional] Command for an external tool (e.g., 'fatoora') to generate the invoice hash.")

    # Command: generate-hash
    hash_parser = subparsers.add_parser("generate-hash", help="Generate the Base64-encoded hash for an invoice from a JSON file.")
    hash_parser.add_argument("--input", required=True, help="Path to the invoice data JSON file.")

    # Command: validate
    val_parser = subparsers.add_parser("validate", help="Validate a ZATCA invoice XML file for well-formedness.")
    val_parser.add_argument("--invoice", required=True, help="Path to the invoice XML file to validate.")

    # Command: generate-api-request
    api_parser = subparsers.add_parser("generate-api-request", help="Generate the JSON request for the Compliance/Reporting API.")
    api_parser.add_argument("--invoice", required=True, help="Path to the signed invoice XML file.")
    api_parser.add_argument("--output", required=True, help="Path for the output API request JSON file.")

    args = parser.parse_args()

    try:
        if args.command == "generate-csr-config":
            generate_csr_config(args.output)
        
        elif args.command == "validate":
            validate_invoice(args.invoice)
        
        elif args.command == "generate-api-request":
            generate_api_request(args.invoice, args.output)

        elif args.command in ["generate", "generate-hash"]:
            with open(args.input, 'r', encoding='utf-8') as f:
                invoice_details = json.load(f)
            
            if args.command == "generate":
                zatca_gen = ZatcaInvoice(invoice_details, private_key_path=args.key, cert_path=args.cert)
                signed_invoice_xml = zatca_gen.generate_signed_invoice(
                    external_hasher_cmd=args.external_hasher,
                    output_path=args.output
                )
                
                if signed_invoice_xml:
                    with open(args.output, "w", encoding="utf-8") as f:
                        f.write(signed_invoice_xml)
                        
                print(f"Successfully generated signed invoice: '{args.output}'")

            elif args.command == "generate-hash":
                zatca_gen = ZatcaInvoice(invoice_details)
                invoice_hash = zatca_gen.get_invoice_hash()
                print("Invoice Hash (Base64):")
                print(invoice_hash)

    except FileNotFoundError as e:
        print(f"\nERROR: File not found - {e.filename}")
        print("Please ensure the required key/certificate and input files exist.")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")

if __name__ == "__main__":
    main()

