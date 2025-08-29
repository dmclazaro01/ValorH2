from confluent_kafka import Producer
import json
def delivery_report(err, msg):
    if err is not None:
        print('Error: {}'.format(err))
    else:
        print('Mensaje enviado a {} [{}]'.format(msg.topic(), msg.partition()))

# Configuración del productor de Kafka
conf = {'bootstrap.servers': '172.16.100.101:9092'}

# Crear una instancia del productor
producer = Producer(conf)

# Tópico al que deseas enviar la información
topic = 'test'

# Mensaje que deseas enviar
read_file = open("data/groups.json", "r")
mensaje = read_file.read()
read_file.close()

mensaje = json.loads(mensaje)
mensaje = json.dumps(mensaje)

# Enviar el mensaje al tópico
producer.produce(topic, key=None, value=mensaje, callback=delivery_report)

# Esperar a que todos los mensajes sean entregados o haya un error
producer.flush()
