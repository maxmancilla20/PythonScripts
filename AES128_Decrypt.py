from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
#from scapy.all import *
#import zlib
import binascii

def cifrar(texto_plano, clave, iv):
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    texto_plano = pad(texto_plano.encode('utf-8'), AES.block_size)
    texto_cifrado = cipher.encrypt(texto_plano)
    return texto_cifrado

def descifrar(texto_cifrado, clave, iv):
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    #texto_plano = unpad(cipher.decrypt(texto_cifrado), AES.block_size)
    texto_plano = cipher.decrypt(texto_cifrado)
    return texto_plano.decode('utf-8')

def extraer_ultimos_4_bytes(texto_hexadecimal):
    # Extraer los últimos 4 caracteres (4 bytes)
    ultimos_4_bytes = texto_hexadecimal[-8:]

    # Eliminar los últimos 4 caracteres del string original
    texto_sin_ultimos_4_bytes = texto_hexadecimal[:-8]

    return ultimos_4_bytes, texto_sin_ultimos_4_bytes

def calcular_crc32(datos):
    # Calcular el CRC32 de los datos
    crc_calculado = binascii.crc32(datos) & 0xFFFFFFFF
    return crc_calculado

def is_k64_frame(frame):
    try:
        return frame.getlayer(0).src=='d4:be:d9:45:22:61'
        #return frame[802.3].src == 'd4:be:d9:45:22:61'
    except:
        return False

def limpiar_ultimos_ceros(cadena):
    # Encuentra la última posición del primer byte diferente de 0x00 desde el final
    indice_no_cero = len(cadena) - 1
    while indice_no_cero >= 0 and (cadena[indice_no_cero] == 0x00 or cadena[indice_no_cero] == ord('0')):
        indice_no_cero -= 1

    # Elimina los bytes con valor de 0x00 o caracteres '0' en ASCII
    nueva_cadena = cadena[:indice_no_cero + 1]

    # Verificar si la longitud es divisible por 2
    if len(nueva_cadena) % 2 != 0:
        # Agregar un '0' al final si la longitud no es divisible por 2
        nueva_cadena += b'0'
        
    return nueva_cadena 
  
# Ejemplo de uso
clave = bytes([0x01] * 16)  # Clave consistente de puros 0x01
iv = bytes([0] * AES.block_size) #IV lleno de 0

# Texto original
#texto_original = "MAXIMILIANO_MT"

# Cifrar el texto original
#texto_cifrado = cifrar(texto_original, clave, iv)
#texto_cifrado = "99aa382769f887165f27f718f3d6c5"
#print(f'Texto cifrado en hexadecimal: {binascii.hexlify(texto_cifrado).decode("utf-8")}')

#condifure scapy incomplete yet.
# Configure Scapy to use the ethernet interface
#conf.iface="Realtek PCIe GbE Family Controller"
# Wait to receive a frame
#frames = sniff(count=8, lfilter=is_k64_frame) #, prn= lambda x:x.show())

"""for  i in range(8):
    frame = frames[i]
    data_len = frame.getlayer(0).len
    # Extract data from frame
    data = bytes(frame)"""

#print(data)   
# Texto hexadecimal
cadena_original = b'a5fa9a80982689f2390235a87e267c3c7046ce570b4234197bbd558532bdc44cb251e3910000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
texto_hexadecimal_con_CRC = limpiar_ultimos_ceros(cadena_original)
#texto_hexadecimal_con_CRC = "a5fa9a80982689f2390235a87e267c3ce4012a4fe41022e3af018bacd653ff5d6bf95bbc"
CRC_Origen, texto_hexadecimal_sin_CRC  = extraer_ultimos_4_bytes(texto_hexadecimal_con_CRC) #separar datos y crc
CRC_Origen = int(CRC_Origen, 16) #convertir CRC_Origen a entero

##print("Origen")
#print(CRC_Origen)

# Convertir a bytes texto_hexadecimal_sin_CRC
texto_hexadecimal_sin_CRC = binascii.unhexlify(texto_hexadecimal_sin_CRC)
CRC_Destino = calcular_crc32(texto_hexadecimal_sin_CRC)

#print("destino")
#print(CRC_Destino)

if CRC_Origen == CRC_Destino:
    # Descifrar el texto cifrado
    texto_recuperado = descifrar(texto_hexadecimal_sin_CRC, clave, iv)
    print(f'Texto descifrado: {texto_recuperado}')
    
else:
    print("El CRC no coincide.")

#primer update
#a5fa9a80982689f2390235a87e267c3c16cedc48c541d3898d891f8cbf762b11faf68b030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
#segundo
#a5fa9a80982689f2390235a87e267c3ceef56ab9fdbe2f804326a3870e81a664de9f1fe60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
#tercer
#a5fa9a80982689f2390235a87e267c3ce4012a4fe41022e3af018bacd653ff5d6bf95bbc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
#cuarto
#
#quinto
#
#sexto
#