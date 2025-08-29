from java.io import BufferedReader, InputStreamReader
from org.apache.nifi.components.state import Scope
from org.apache.nifi.processor.io import InputStreamCallback, OutputStreamCallback
from java.nio.charset import StandardCharsets
from org.apache.commons.io import IOUtils

class PyInputStreamCallback(InputStreamCallback):
    def __init__(self):
        self.response_data = None

    def process(self, inputStream):
        self.response_data = IOUtils.toString(inputStream, StandardCharsets.UTF_8)

class PyOutputStreamCallback(OutputStreamCallback):
    def __init__(self, content):
        self.content = content

    def process(self, outputStream):
        outputStream.write(self.content.encode("utf-8"))

flowFile = session.get()
if flowFile != None:
    try:
        attr = flowFile.getAttribute('id_ioc')
        stateManager = context.getStateManager()
        stateMap = stateManager.getState(Scope.CLUSTER)
        updatedStateMap = stateMap.toMap()
        if stateMap.version == -1:
            newMap = {'id_ioc': attr}
            stateManager.setState(newMap, Scope.CLUSTER)
            pyOutStreamCallback = PyOutputStreamCallback(updatedStateMap.toString())
            flowFile = session.write(flowFile, pyOutStreamCallback)
            session.transfer(flowFile, REL_FAILURE)
        else:
            updatedStateMap['id_ioc'] = attr
            pyOutStreamCallback = PyOutputStreamCallback(updatedStateMap.toString())
            flowFile = session.write(flowFile, pyOutStreamCallback)
            session.transfer(flowFile, REL_SUCCESS)
    except Exception as e:
        log.error('Error al actualizar el estado: {}'.format(str(e)))
        session.transfer(flowFile, REL_FAILURE)
else:
    pass
