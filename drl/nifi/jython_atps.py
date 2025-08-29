from HTMLParser import HTMLParser
import os
import json
from org.apache.commons.io import IOUtils
from java.nio.charset import StandardCharsets
from org.apache.nifi.processor.io import StreamCallback

class MyHTMLParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.is_data_cell = False
        self.current_data = ''
        self.data_cells = []
        self.column_found = False

    def handle_starttag(self, tag, attrs):
        if tag == 'td':
            self.is_data_cell = True
            self.current_data = ''

    def handle_endtag(self, tag):
        if tag == 'td':
            self.is_data_cell = False
            if self.column_found:
                self.data_cells.append(self.current_data)

    def handle_data(self, data):
        if self.is_data_cell:
            self.current_data += data
            if "Toolset / Malware" in self.current_data.strip():
                self.column_found = True

def search_apt(malware_value, parser):
    target_column = None
    log.error("target columnnnnnnnnnnn")
    for i, cell_data in enumerate(parser.data_cells):
        if "Toolset / Malware" in cell_data.strip():
            target_column = i
            break

    if target_column is not None:
        for i in range(target_column, len(parser.data_cells), target_column):
            text_toolset = parser.data_cells[i].strip().upper()
            if malware_value.upper() in text_toolset:
                return parser.data_cells[i]
    return None

class PyStreamCallback(StreamCallback):
    def __init__(self):
        self.shouldTransfer = True

    def process(self, inputStream, outputStream):
        text = IOUtils.toString(inputStream, StandardCharsets.UTF_8)
        response = json.loads(text)
        parser = MyHTMLParser()
        directory = '/home/nifi/html/atps.html'
        log.error("leyendo ficherooooooooooooooooooooooooooooooooo")
        with open(directory, 'r') as file:
            html_content = file.read()
        parser.feed(html_content)
        log.error("leidoooooooooooooooo")


        malware_value = response.get('details', {}).get('malware')
        if malware_value:
            response['threat_actor'] = search_apt(malware_value, parser)
        
        
        outputStream.write(json.dumps(response, indent=4).encode('utf-8'))

flowFile = session.get()
if flowFile != None:
    callback = PyStreamCallback()
    flowFile = session.write(flowFile, callback)
    session.transfer(flowFile, REL_SUCCESS)
else:
    session.transfer(flowFile, REL_FAILURE)
