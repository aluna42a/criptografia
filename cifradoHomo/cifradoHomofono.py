import random

# Definimos el diccionario homofónico con los valores proporcionados
homofonic_dict = {
    'A': ['00101010', '11010101', '10101010'],
    'B': ['01010101', '10110101', '11001100'],
    'C': ['00110011', '11001101', '10110001'],
    'D': ['01100110', '10011001', '11011011'],
    'E': ['00111100', '11000011', '10111101', '11110000'],
    'F': ['01001111', '10100101', '11000110'],
    'G': ['01111000', '10000111', '11101010'],
    'H': ['00101101', '11010010', '10101100'],
    'I': ['01011010', '10101001', '11001011'],
    'J': ['01101001', '10010110', '11100101'],
    'K': ['00110101', '11001010', '10110110'],
    'L': ['01001011', '10111000', '11011101'],
    'M': ['01110110', '10001001', '11101100'],
    'N': ['00111011', '11000100', '10111010'],
    'Ñ': ['01011100', '10100011', '11011110'],
    'O': ['01100010', '10011101', '11100001', '11010111'],
    'P': ['00101111', '11011000', '10101111'],
    'Q': ['01010011', '10110000', '11010011'],
    'R': ['01101101', '10010010', '11101111'],
    'S': ['00111111', '11000001', '10111110'],
    'T': ['01000101', '10111111', '11000111'],
    'U': ['01110001', '10001110', '11110011'],
    'V': ['00101001', '11010110', '10101011'],
    'W': ['01011001', '10100110', '11011001'],
    'X': ['01100101', '10011010', '11100110'],
    'Y': ['00110110', '11001001', '10110111'],
    'Z': ['01001101', '10110011', '11001110'],
    ' ': ['00000000']  # Añadimos un sustituto para el espacio
}

# Invertimos el diccionario para el descifrado
reverse_homofonic_dict = {v: k for k, values in homofonic_dict.items() for v in values}

def cifrar(mensaje):
    mensaje = mensaje.upper()
    cifrado = []
    for letra in mensaje:
        if letra in homofonic_dict:
            # Elegimos un sustituto aleatorio para la letra
            sustituto = random.choice(homofonic_dict[letra])
            cifrado.append(sustituto)
        else:
            # Si la letra no está en el diccionario, la dejamos igual
            cifrado.append(letra)
    return ' '.join(cifrado)

def descifrar(mensaje_cifrado):
    cifrado = mensaje_cifrado.split()
    descifrado = []
    for sustituto in cifrado:
        if sustituto in reverse_homofonic_dict:
            descifrado.append(reverse_homofonic_dict[sustituto])
        else:
            # Si el sustituto no está en el diccionario, lo dejamos igual
            descifrado.append(sustituto)
    return ''.join(descifrado)

# Función principal para interactuar con el usuario
def main():
    print("Bienvenido al sistema de cifrado homofónico.")
    while True:
        print("\n¿Qué deseas hacer?")
        print("1. Cifrar un mensaje")
        print("2. Descifrar un mensaje")
        print("3. Salir")
        opcion = input("Elige una opción (1, 2 o 3): ")

        if opcion == '1':
            mensaje = input("Ingresa el mensaje que deseas cifrar: ")
            mensaje_cifrado = cifrar(mensaje)
            print(f"\nMensaje cifrado: {mensaje_cifrado}")
        elif opcion == '2':
            # Mostramos la tabla de homofónicos
            print("\nTabla de homofónicos (para cifrar):")
            for letra, sustitutos in homofonic_dict.items():
                print(f"{letra}: {', '.join(sustitutos)}")
            print("Ejemplo de mensaje cifrado:")
            print("11001100 10001110 00111100 10111010 10101010 10111110 00000000 11000111 00101010 01101101 01100110 00111100 11000001")
            mensaje_cifrado = input("Ingresa el mensaje cifrado que deseas descifrar: ")
            mensaje_descifrado = descifrar(mensaje_cifrado)
            print(f"\nMensaje descifrado: {mensaje_descifrado}")
        elif opcion == '3':
            print("¡Hasta luego!")
            break
        else:
            print("Opción no válida. Por favor, elige 1, 2 o 3.")

# Ejecutamos la función principal
if __name__ == "__main__":
    main()