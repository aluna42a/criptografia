#definir posiciones abecedario 
#abecedario=[a,b,c,d,e,......,z]
##pos={letra: }

def obtener_posicion_letra(letra):
    abecedario = "abcdefghijklmnopqrstuvwxyz"
    posiciones = {letra: i for i, letra in enumerate(abecedario)}
    return posiciones.get(letra, letra)  # Devuelve la misma letra si no está en el diccionario

def cifrar_texto(texto, n):
    abecedario = "abcdefghijklmnopqrstuvwxyz"
    texto_cifrado = []
    for letra in texto:
        if letra in abecedario:
            nueva_pos = (obtener_posicion_letra(letra) + n) % 26
            texto_cifrado.append(abecedario[nueva_pos])
        else:
            texto_cifrado.append(letra)  # Mantiene los caracteres que no están en el abecedario
    return ''.join(texto_cifrado)

def descifrar_texto(texto_cifrado, n):
    abecedario = "abcdefghijklmnopqrstuvwxyz"
    texto_descifrado = []
    for letra in texto_cifrado:
        if letra in abecedario:
            nueva_pos = (obtener_posicion_letra(letra) - n) % 26
            texto_descifrado.append(abecedario[nueva_pos])
        else:
            texto_descifrado.append(letra)
    return ''.join(texto_descifrado)


texto = input("Ingresa un texto para cifrar: ")
n = int(input("Ingresa el número de desplazamiento: "))
cifrado = cifrar_texto(texto, n)
print(f"Texto cifrado: {cifrado}")
print(f"Texto descifrado: {descifrar_texto(cifrado, n)}")
