from netmiko import ConnectHandler
def extract_connfig(output):
    device = ConnectHandler(device_type='cisco_ios', ip='192.168.109.253', username='cisco', password='cisco')
    output = device.send_command("show run")
    device.disconnect() 