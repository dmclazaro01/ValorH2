from org.apache.commons.io import IOUtils
from java.nio.charset import StandardCharsets
from org.apache.nifi.processor.io import StreamCallback
import json

class PyStreamCallback(StreamCallback):
    def __init__(self):
        self.shouldTransfer = True

    def process(self, inputStream, outputStream):
        text = IOUtils.toString(inputStream, StandardCharsets.UTF_8)
        response = json.loads(text)

        # Realizar el procesamiento deseado
        analysis_data = response.get("analysis", {})
        sample_data = response.get("sample", {})
        signatures_list = response.get("signatures", [])

        sha256_muestra = sample_data.get("sha256", "")

        ttp_data = set()
        tactic_list = set()

        for signa in signatures_list:
            ttp_values = signa.get("ttp", [])
            for ttp_value in ttp_values:
                if ttp_value and "." in ttp_value:
                    tactic_list.add(ttp_value)
                elif ttp_value:
                    ttp_data.add(ttp_value)

        # Verificar si ttp_data y tactic_list están vacíos
        if not ttp_data and not tactic_list:
            self.shouldTransfer = False
            return

        desc = next((signature.get("desc", "") for signature in signatures_list if signature.get("desc")), "")

        malware_aliases = set(analysis_data.get("malware_alias", []))

        iocs_list = response.get("targets", [])
        iocs = [target.get("iocs", []) for target in iocs_list]

        malware_json = {
            "details": {
                "desc": desc,
                "iocs": iocs,
                "ioctype": analysis_data.get("ioctype", ""),
                "SHA256": sha256_muestra,
                "threat_type": analysis_data.get("threat_type", ""),
                "malware": analysis_data.get("malware", ""),
                "malware_alias": list(malware_aliases),
                "family": analysis_data.get("family", ""),
            },
            "vulnerability": {},
            "techniques": list(ttp_data),
            "tactic": list(tactic_list),
            "tool": {},
            "threat_actor": [],
            "asset": {},
            "relationships": {},
        }

        outputStream.write(json.dumps(malware_json, indent=4).encode('utf-8'))

flowFile = session.get()
if flowFile != None:
    callback = PyStreamCallback()
    flowFile = session.write(flowFile, callback)
    if callback.shouldTransfer:
        flowFile = session.putAttribute(flowFile, "filename", flowFile.getAttribute('filename') + "_processed")
        session.transfer(flowFile, REL_SUCCESS)
    else:
        session.transfer(flowFile, REL_FAILURE)
