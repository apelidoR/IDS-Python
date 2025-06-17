
from idsstarly import * 
file_manager = FileManager()
ids = IntrusionDetectionSystem(file_manager)
ids.limite_icmp = 900
print(ids.limite_icmp)

ids.iniciar_monitoramento()