import json
from prettytable import PrettyTable

def printing(output):
    with open('config-C3745.json') as value:
        dictionary = json.load(value)

    table = PrettyTable()
    table.field_names = ["Attribute", "value", "Fix"]

    for key in dictionary:
        if type(dictionary[key]) == type({}):
            for key2 in dictionary[key]:
                table.add_row([key2, dictionary[key][key2],"no fix"], divider=True)
        else:
            table.add_row([key, dictionary[key],"no fix"], divider=True)


    #print(table)