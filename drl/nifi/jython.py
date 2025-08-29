from org.apache.nifi.processor.io import InputStreamCallback
from java.io import BufferedReader, InputStreamReader
from org.apache.nifi.components.state import Scope

class PyInputStreamCallback(InputStreamCallback):
    def __init__(self):
        pass

    def process(self, inputStream):
        reader = BufferedReader(InputStreamReader(inputStream))
        try:
            # Puedes leer y procesar el contenido aquí si es necesario
            pass
        finally:
            reader.close()

flowFileList = session.get(2)
if not flowFileList.isEmpty():
    attr_1 = flowFileList.get(0).getAttribute('id_ioc')
    attr_2 = flowFileList.get(1).getAttribute('id_ioc')
    if attr_1 == attr_2:
        session.transfer(flowFileList, REL_SUCCESS)
    else:
        session.transfer(flowFileList, REL_FAILURE)