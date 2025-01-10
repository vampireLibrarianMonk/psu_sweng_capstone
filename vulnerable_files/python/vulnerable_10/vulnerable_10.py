# Python (XML External Entity Injection Vulnerability)
from lxml import etree

def parse_xml(xml_data):
    try:
        # Parse the XML data without disabling external entity references
        parser = etree.XMLParser()
        root = etree.fromstring(xml_data, parser=parser)
        return root
    except Exception as e:
        print(f"Error parsing XML: {e}")
        return None

if __name__ == "__main__":
    # Simulate receiving XML data from an untrusted source
    user_input = input("Enter XML data: ")
    document = parse_xml(user_input)
    if document is not None:
        print("XML parsed successfully.")
