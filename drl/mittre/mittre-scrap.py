import requests
import json
from bs4 import BeautifulSoup
import re


URL = "https://attack.mitre.org/"
URL_TECHNIQUES = URL + "techniques/"

def get_all(return_data):
    pattern = r'\d+'
    tactics_count = []
    tactics_name = []
    tactics_id = []
    techniques_name = []
    mittre = {}
    subtechniques = {}
    response = requests.get(URL)
    soup = BeautifulSoup(response.text, "html.parser")
    matrix = soup.find("div", {"class": "matrix-container p-3"})
    tactics_html = matrix.find_all("td", {"class": "tactic name"})
    for i in tactics_html:
        name = i.find("a").text
        tactid = i.find("a")["title"]
        tactics_name.append(name)
        tactics_id.append(tactid)
    tactics_count_html = matrix.find_all("td", {"class": "tactic count"})
    for i in tactics_count_html:
        number = re.findall(pattern, i.text)
        tactics_count.append(int(number[0]))
    techniques_html = matrix.find_all("table", {"class": "techniques-table"})
    for tactic in tactics_name:
        mittre[tactic] = {"tactid": tactics_id[tactics_name.index(tactic)]}
    index = 0
    for techniques_colum in techniques_html:
        techniques_rows = techniques_colum.find_all("tr", {"class": "technique-row"})
        for techniques_row in techniques_rows:
                supertechnique = techniques_row.find("table",{"class": "supertechnique"})
                if (supertechnique == None):
                    technique_cell = techniques_row.find("div", {"class": "technique-cell"})
                    technique_cell_a = technique_cell.find("a")
                    technique_name = technique_cell_a.text
                    techniques_name.append(technique_name)
                    tid = technique_cell_a["title"]
                    data = {"tid": tid}
                    mittre[tactics_name[index]][technique_name] = data
                else:
                    technique_cell = supertechnique.find("div")
                    technique_cell_a = technique_cell.find("a")
                    technique_name = technique_cell_a.text
                    technique_name = technique_name.split("\xa0")[0]
                    techniques_name.append(technique_name)
                    tid = technique_cell_a["title"]
                    subtechniques_html = techniques_row.find_all("div", {"class": "subtechnique"})
                    subtechniques = {}
                    for subtechnique in subtechniques_html:
                        subtechnique_a = subtechnique.find("a")
                        subtechnique_name = subtechnique_a.text
                        s_tid = subtechnique_a["title"]
                        subtechniques[subtechnique_name] = {"stid": s_tid}
                    data = {"tid": tid, "subtechniques": subtechniques}
                    mittre[tactics_name[index]][technique_name] = data
        mittre[tactics_name[index]]["count"] = tactics_count[index]
        index += 1
    mittre["count"] = len(tactics_count)
    json_string = json.dumps(mittre,indent=4)
    with open("data/mittre_all.json", "w") as outfile:
        outfile.write(json_string)
    if (return_data == 0):
        return mittre
    elif (return_data == 1):
        return tactics_name,tactics_id
    elif (return_data == 2):
        return techniques_name
    

def get_all_tactics(num=1):
    data = {}
    tactics,ids = get_all(num)
    for i in tactics:
        data[i] = {"tactid": ids[tactics.index(i)]}
    data["tactics"] = tactics
    data["count"] = len(tactics)
    json_string = json.dumps(data,indent=4)
    with open("data/tactics.json", "w") as outfile:
        outfile.write(json_string)
    return data

def get_tactic(tactid):
    tactics,ids = get_all(1)
    if (tactid not in ids):
        print("Tactica no encontrada")
        return
    url = URL + "tactics/" + tactid + "/"
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    tactic = {}
    tactic["tactid"] = tactid
    name = soup.find("h1").text
    name = name.split("\n")[1]
    name = re.sub(r"^\s+", "", name)
    tactic["name"] = name
    description = soup.find("div",{"class":"description-body"})
    description_text = description.findAll("p")
    description = ""
    for t in description_text:
        description += t.text
    tactic["description"] = description
    techniques = {}
    techniques_html = soup.find("tbody")
    techniques_html = techniques_html.find_all("tr",{"class":"technique"})
    for technique in techniques_html:
        technique_data = technique.find_all("td")
        technique_id_a = technique_data[0].find("a")
        if (technique_id_a == None):
            continue
        technique_id = technique_id_a.text
        technique_id = technique_id.replace(" ","")
        technique_name = technique_data[1].find("a").text
        description = technique_data[2].text
        description = description.split("\n")[1]
        description = re.sub(r"^\s+", "", description)
        techniques[technique_name] = {"tid": technique_id, "description": description}
    tactic["techniques"] = techniques
    json_string = json.dumps(tactic,indent=4)
    with open("data/tactic.json", "w") as outfile:
        outfile.write(json_string)
    return tactic


def get_all_techniques(num=2):
    data = {}
    techniques = get_all(num)
    data["techniques"] = techniques
    data["count"] = len(techniques)
    json_string = json.dumps(data,indent=4)
    with open("data/techniques.json", "w") as outfile:
        outfile.write(json_string)
    return data

def get_technique(tid,st_description=False):
    url = URL_TECHNIQUES + tid + "/"
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    technique = {}
    technique["tid"] = tid
    name = soup.find("h1").text
    name = name.split("\n")[1]
    name = re.sub(r"^\s+", "", name)
    technique["name"] = name
    description = soup.find("div",{"class":"description-body"})
    description_text = description.findAll("p")
    description = ""
    for t in description_text:
        description += t.text
    technique["description"] = description
    subtechniques_card = soup.find("div",{"id":"subtechniques-card-body"})
    if (subtechniques_card != None):
        subtechniques = {}
        subtechniques_html = subtechniques_card.find("tbody")
        subtechniques_html = subtechniques_html.find_all("tr")
        for subtechnique in subtechniques_html:
            subtechnique_data = subtechnique.find_all("td")
            subtechnique_id = subtechnique_data[0].find("a").text
            subtechnique_id = subtechnique_id.replace(" ","")
            subtechnique_name = subtechnique_data[1].find("a").text
            if (st_description == False):
                subtechniques[subtechnique_name] = {"stid": subtechnique_id}
            else:
                subtid = subtechnique_id.split(".")
                url_subtechnique = url + subtid[1] + "/"
                response_subtechnique = requests.get(url_subtechnique)
                soup_subtechnique = BeautifulSoup(response_subtechnique.text, "html.parser")
                subtechnique_description = soup_subtechnique.find("div",{"class":"description-body"})
                subtechnique_description = subtechnique_description.find("p").text
                subtechniques[subtechnique_name] = {"stid": subtechnique_id, "description": subtechnique_description}
        technique["subtechniques"] = subtechniques
    json_string = json.dumps(technique,indent=4)
    with open("data/technique.json", "w") as outfile:
        outfile.write(json_string)
    return json_string


def get_all_tids():
    mittre = get_all(0)
    mittre.pop("count")
    tactics = mittre.keys()
    tactics = list(tactics)
    techniques_id = []
    for i in tactics:
        techniques_data = mittre[i]
        techniques = mittre[i].keys()
        techniques = list(techniques)
        del techniques[-1]
        print(techniques_data)
        for j in techniques:
            techniques_id.append(techniques_data[j]["tid"])
    return techniques_id


def add_technique(tid):
    tactics = get_all_tactics()
    print("Tacticas disponibles: ")
    print(tactics["tactics"])
    tactics_array = tactics["tactics"]
    tactic = input("Introduzca la tactica a la que pertenece: ")
    if (tactic not in tactics_array):
        print("Tactica no encontrada")
        return
    mittre = get_all(0)
    techniques = mittre[tactic]
    techniques.pop("count")
    techniques_array = techniques.keys()
    techniques_array = list(techniques_array)
    techniques_ids = []
    tids = get_all_tids()
    for i in techniques_array:
        techniques_ids.append(techniques[i]["tid"])
    for i in techniques_array:
        techniques_array[techniques_array.index(i)] = i + ":" + techniques[i]["tid"] + ""
    print("Tecnicas disponibles: ")
    print(techniques_array)
    id = tid
    if (id in tids):
        print("Tecnica con id ya existente")
        return
    name = input("Introduzca el nombre de la tecnica: ")
    description = input("Introduzca la descripcion de la tecnica: ")
    data = {"tid": id, "description": description}
    mittre[tactic][name] = data
    json_string = json.dumps(mittre,indent=4)
    with open("data/mittre_all.json", "w") as outfile:
        outfile.write(json_string)
    print("Tecnica añadida correctamente")
    return mittre

def get_groups():
    url = URL + "groups/"
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    groups = {}
    groups_html = soup.find("tbody")
    groups_html = groups_html.find_all("tr")
    for group in groups_html:
        group_data = group.find_all("td")
        group_id = group_data[0].find("a").text
        group_id = group_id.replace(" ","")
        group_name = group_data[1].find("a").text
        group_name = group_name[1:-1]
        group_assocc = group_data[2].text
        group_assocc = group_assocc.replace("\n","")
        group_assoc_data = []
        if group_assocc != "":
            group_assocc = group_assocc.split(",")
            for i in group_assocc:
                group_assoc_data.append(i.strip())
        description = group_data[3].find("p").text
        groups[group_name] = {"gid": group_id, "assoc": group_assoc_data,"description": description}
    json_string = json.dumps(groups,indent=4)
    with open("data/groups.json", "w") as outfile:
        outfile.write(json_string)
    return groups

    






def main():
    #get_all(0)
    #get_all_techniques()
    #get_all_tactics()
    #get_tactic("TA0040")
    #get_technique("T1594",True)
    #add_technique("T1599")
    get_groups()

if __name__ == '__main__':
    main()