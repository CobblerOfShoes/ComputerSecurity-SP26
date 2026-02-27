# Alex Schumann
# Computer Security CSE-40567

import argparse
from collections import Counter

MAX_CIPHER_LENGTH = 100

def rotateText(text: str, rotation: int):
  rotatedText = ""
  for c in text:
    if 'A' <= c <= 'Z':
      newOrd = ord('A') + ((ord(c) - ord('A') + rotation) % 26)
      rotatedText += chr(newOrd)
  return rotatedText

# Iterate through the 25 possible substitution ciphers on the alphabet
#  Since there are 26 letters, then you can shift each letter between 0 and 25 times
def generateSubstitutionCipher(plainText: str):
  for i in range(0,26):
    yield rotateText(plainText, i)

# If both strings consist of the same set of characters, then one is a permutation of the other
def checkPermutationCipher(cipherText: str, substitutedText: str):
  cipherTextCharCounts = Counter(cipherText)
  substitutedTextCharCounts = Counter(substitutedText)
  if cipherTextCharCounts == substitutedTextCharCounts:
    return True
  else:
    return False

def checkAncientCypher():
  parser = argparse.ArgumentParser(
          prog='AncientCypherChecker',
          description='Check if a cypher text can produce given plaintext. SYNTAX: ./prog --file INPUT_FILE',
  )
  parser.add_argument('--file', type=str,
                      help="The filename containing the ciphertext on the first line and plaintext on the second line.")

  args = parser.parse_args()
  inputFile = args.file

  cipherExists = False

  with open(inputFile, 'r') as file:
    cipherText = file.readline().strip()
    plainText = file.readline().strip()

    # Both texts must be equal length and less than MAX_CIPHER_LENGTH characters
    cipherTextLength = len(cipherText)
    plainTextLength = len(plainText)
    if (cipherTextLength != plainTextLength) or (cipherTextLength > MAX_CIPHER_LENGTH) or (plainTextLength > MAX_CIPHER_LENGTH):
      print("NO")
      #print("Texts are invalid length")
      return 1

    # Both texts must contain capital letters
    if not (cipherText.isalpha() and cipherText.isupper() and plainText.isalpha() and plainText.isupper()):
      print("NO")
      #print("Texts contain illegal characters")
      return 1

    # From this point, we check for a possible cipher
    for substitutionText in generateSubstitutionCipher(plainText):
      cipherExists = cipherExists or checkPermutationCipher(cipherText, substitutionText)
      if cipherExists:
        break

  if cipherExists:
    print("YES")
    return 0
  else:
    print("NO")
    return 1

if __name__ == '__main__':
  checkAncientCypher()