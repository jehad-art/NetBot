import json
from prettytable import PrettyTable

def structure(output):
  file = open("original-config.txt", "r")
  conf_string=""
  for character in file:
    conf_string += character
  file.close() 

  word_check = []
  flag = 0
  for line in conf_string.splitlines():
      line_check = line.split()
      for word in line_check:
        if word == "!" or word == "no" or word == "boot-end-marker" or word == "boot-start-marker" or word == "memory-size" or word == "service" or word == "Building" or word == "Current":
          break
        elif word == "ip" and (line_check[1] == "domain" or line_check[1] == "ssh" or line_check[1] == "address" or line_check[1] == "http"):
          word_check.append(line_check)
          #print(line)
          break
        elif word == "ip" and (line_check[1] != "domain" or line_check[1] == "ssh" or line_check[1] == "address" or line_check[1] == "http"):
          break
        else:
          word_check.append(line_check)
          #print(line)
          break


  structured_config={}
  fix={}
  security_attribute_general = ["version","password-encryption","hostname","enable-login","aaa-auth","icmp-DOS-protect","domain-name","username","SSH-version"]
  security_attribute_interface = []
  counter = 0
  for fetch in word_check:
    if word_check[counter][0] == "version":
      structured_config[security_attribute_general[0]] = word_check[counter][1]
      fix[0] = "-"
    elif word_check[counter][0] == "hostname":
      structured_config[security_attribute_general[2]] = word_check[1][1]
      fix[1] = "-"
    elif word_check[counter][0] == "enable":
      if word_check[2][1] == "password":
        structured_config[security_attribute_general[3]] = "Unencrypted"
        fix[2] = "The enable should use either secret or get service password enabled"
      elif word_check[2][1] == "secret":
        structured_config[security_attribute_general[3]] = "Encrypted"
        fix[2] = "-"
    elif word_check[counter][0] == "ip" and word_check[counter][1] == "domain":
      structured_config[security_attribute_general[6]] = word_check[counter][3]
      fix[3] = "-"
    elif word_check[counter][0] == "username":
      structured_config[security_attribute_general[7]] = word_check[counter][1]
      if word_check[counter][2] == "password" and int(word_check[counter][3]) < 7:
        fix[4] = "The password encryption level is less than 7 which is breakable. Reconfigure it to be 7,8 or 9"
      else:
        fix[4] = "-"
    elif word_check[counter][0] == "ip" and word_check[counter][1] == "ssh":
      structured_config[security_attribute_general[8]] = word_check[counter][3]
      fix[5] = "-"

    counter += 1
  structured_config[security_attribute_general[1]] = "not configured"
  if structured_config[security_attribute_general[1]] == "not configured":
    fix[6] = "Service password encryption should be configured"
  else:
    fix[6] = "-"
  structured_config[security_attribute_general[4]] = "not configured"
  if structured_config[security_attribute_general[4]] == "not configured":
    fix[7] = "Access device with no authentication is highly risky. aaa model must be configured"
  else:
    fix[7] = "-"
  structured_config[security_attribute_general[5]] = "not configured"
  if structured_config[security_attribute_general[5]] == "not configured":
    fix[8] = "Hacker can cause an ICMP DOS attack if no rate limmit is configured"
  else:
    fix[8] = "-"
    
  table = PrettyTable()
  table.field_names = ["Attribute", "value", "Fix"]
  counter2 = 0
  for key in structured_config:
      if type(structured_config[key]) == type({}):
          for key2 in structured_config[key]:
              table.add_row([key2, structured_config[key][key2],fix[counter2]], divider=True)
      else:
          table.add_row([key, structured_config[key],fix[counter2]], divider=True)
      counter2 += 1

  print(table)

