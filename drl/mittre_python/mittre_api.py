# pip install mitreattack-python
# For download the MITRE ATT&CK data download_attack_stix
from mitreattack.stix20 import MitreAttackData

def get_tactics(mitre_attack_data):
    return mitre_attack_data.get_tactics(remove_revoked_deprecated=True)

def get_techniques(mitre_attack_data):
    return mitre_attack_data.get_techniques(remove_revoked_deprecated=True)
    
def get_sub_techniques(mitre_attack_data,tid):
    return mitre_attack_data.get_subtechniques_of_technique(tid)

def get_objects_by_name(mitre_attack_data, name):
    return mitre_attack_data.get_objects_by_name(name,"attack-pattern")

def main():
    mitre_attack_data = MitreAttackData("attack-releases/stix-2.0/v14.1/enterprise-attack.json")
    object_name = "Masquerading"
    technique_list = get_objects_by_name(mitre_attack_data, object_name)
    technique = technique_list[0]
    print(technique.serialize())
    tid = technique.get("external_references")[0].get("external_id")
    print(f"El tid es: {tid}")
    id = technique.get("id")
    subtechniques = get_sub_techniques(mitre_attack_data,id)
    subtechniques_list = []
    print(f"Sub-techniques of {tid} ({len(subtechniques)}):")
    for s in subtechniques:
        sub = s["object"]
        subtechniques_list.append(sub.name)
    print(f"Subtechniques list: {subtechniques_list}")
    tactics = get_tactics(mitre_attack_data)
    tactics_names = []
    for t in tactics:
        tactics_names.append(t.name)
    print(f"Tactics: {tactics_names}")



if __name__ == "__main__":
    main()