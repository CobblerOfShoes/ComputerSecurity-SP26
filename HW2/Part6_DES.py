import argparse

class DES_ECB_Cipher():
  pc1Table = [57, 49, 41, 33, 25, 17, 9,
              1, 58, 50, 42, 34, 26, 18,
              10, 2, 59, 51, 43, 35, 27,
              19, 11, 3, 60, 52, 44, 36,
              63, 55, 47, 39, 31, 23, 15,
              7, 62, 54, 46, 38, 30, 22,
              14, 6, 61, 53, 45, 37, 29,
              21, 13, 5, 28, 20, 12, 4]

  numShiftsPerIteration = [1, 1, 2, 2, 2, 2, 2, 2,
                           1, 2, 2, 2, 2, 2, 2, 1]

  pc2Table = [14, 17, 11, 24, 1, 5,
              3, 28, 15, 6, 21, 10,
              23, 19, 12, 4, 26, 8,
              16, 7, 27, 20, 13, 2,
              41, 52, 31, 37, 47, 55,
              30, 40, 51, 45, 33, 48,
              44, 49, 39, 56, 34, 53,
              46, 42, 50, 36, 29, 32]

  ipTable = [58, 50, 42, 34, 26, 18, 10, 2,
             60, 52, 44, 36, 28, 20, 12, 4,
             62, 54, 46, 38, 30, 22, 14, 6,
             64, 56, 48, 40, 32, 24, 16, 8,
             57, 49, 41, 33, 25, 17,  9, 1,
             59, 51, 43, 35, 27, 19, 11, 3,
             61, 53, 45, 37, 29, 21, 13, 5,
             63, 55, 47, 39, 31, 23, 15, 7]

  ipInvTable = [40, 8, 48, 16, 56, 24, 64, 32,
                39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41,  9, 49, 17, 57, 25]

  expansionTable = [32, 1, 2, 3, 4, 5,
                    4, 5, 6, 7, 8, 9,
                    8, 9, 10, 11, 12, 13,
                    12, 13, 14, 15, 16, 17,
                    16, 17, 18, 19, 20, 21,
                    20, 21, 22, 23, 24, 25,
                    24, 25, 26, 27, 28, 29,
                    28, 29, 30, 31, 32, 1]

  s1Box = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]

  s2Box = [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]]

  s3Box = [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12, 11]]

  s4Box = [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 10, 14, 9, 2],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14, 4]]

  s5Box = [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3, 15]]

  s6Box = [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13, 6]]

  s7Box = [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12, 7]]

  s8Box = [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11, 5]]

  sBoxes = [s1Box, s2Box, s3Box, s4Box, s5Box, s6Box, s7Box, s8Box]

  pBox = [16, 7, 20, 21, 29, 12, 28, 17,
          1, 15, 23, 26, 5, 18, 31, 10,
          2, 8, 24, 14, 32, 27, 3, 9,
          19, 13, 30, 6, 22, 11, 4, 25]

  def __init__(self):
    pass

  def _initialPermutation(self, block: int) -> int:
    permutedBlock = 0
    for i in range(64):
      permutedBlock <<= 1
      permutedBlock |= (block >> (64 - self.ipTable[i])) & 1
    return permutedBlock

  def _inverseInitialPermutation(self, block: int) -> int:
    permutedBlock = 0
    for i in range(64):
      permutedBlock <<= 1
      permutedBlock |= (block >> (64 - self.ipInvTable[i])) & 1
    return permutedBlock

  # Reduce the key from 64 bits down to the effective 56 bits by applying the PC-1 table
  def _reduceKey(self, key: int) -> int:
    # Permute the key using the PC-1 table to get the 56-bit key
    permutedKey = 0
    for i in range(56):
      permutedKey <<= 1
      permutedKey |= (key >> (64 - self.pc1Table[i])) & 1
    return permutedKey

  # Generate the 16 subkeys for the DES algorithm
  def generateSubkeys(self, key: int) -> list[int]:
    # Get the 56 bit effective key
    key = self._reduceKey(key)
    bits = f"{key:056b}"
    formatted = " ".join(bits[i:i+8] for i in range(0, 56, 8))
    print(f"Reduced key: {formatted}")

    # Get the initial left and right halves of the key
    leftHalf = (key >> 28) & 0x0FFFFFFF  # Extract the left half (28 bits)
    rightHalf = key & 0x0FFFFFFF  # Extract the right half (28 bits)

    subkeys = []
    for i in range(16):
      # Perform a circular left shift on both halves
      numShifts = self.numShiftsPerIteration[i]
      newLeftHalf = ((leftHalf << numShifts) | (leftHalf >> (28 - numShifts))) & 0x0FFFFFFF
      newRightHalf = ((rightHalf << numShifts) | (rightHalf >> (28 - numShifts))) & 0x0FFFFFFF
      leftHalf, rightHalf = newLeftHalf, newRightHalf
      # Combine the halves and apply the PC-2 table to get the subkey for this round
      combinedKey = (leftHalf << 28) | rightHalf
      subkey = 0
      for j in range(48):
        subkey <<= 1
        subkey |= (combinedKey >> (56 - self.pc2Table[j])) & 1
      subkeys.append(subkey)

    # Display each subkey in binary format for debugging
    for i, subkey in enumerate(subkeys):
      bits = f"{subkey:048b}"
      formatted = " ".join(bits[j:j+6] for j in range(0, 48, 6))
      print(f"Subkey {(i + 1):02d}: {formatted}")
    return subkeys

  # Run the provided text through the S-boxes and P-box to get the output of the f-function
  def _fFunction(self, rightHalf: int, subkey: int) -> int:
    # Check size of rightHalf and subkey
    rightHalf = rightHalf & 0xFFFFFFFF  # Ensure rightHalf is 32 bits
    subkey = subkey & 0xFFFFFFFFFFFF  # Ensure subkey is 48 bits

    # Expand the right half from 32 bits to 48 bits using the expansion table
    expandedRightHalf = 0
    for i in range(48):
      expandedRightHalf <<= 1
      expandedRightHalf |= (rightHalf >> (32 - self.expansionTable[i])) & 1

    xored = expandedRightHalf ^ subkey

    # Run the result through the S-boxes to get a 32-bit output
    sBoxOutput = 0
    for i in range(8):
      sixBits = (xored >> (42 - 6 * i)) & 0x3F  # Extract 6 bits for this S-box
      row = ((sixBits >> 5) << 1) | (sixBits & 1)  # First and last bits
      col = (sixBits >> 1) & 0xF  # Middle four bits
      sBoxValue = self.sBoxes[i][row][col]
      sBoxOutput <<= 4
      sBoxOutput |= sBoxValue

    # Permute the S-box output using the P-box to get the final output of the f-function
    fFunctionOutput = 0
    for i in range(32):
      fFunctionOutput <<= 1
      fFunctionOutput |= (sBoxOutput >> (32 - self.pBox[i])) & 1

    return fFunctionOutput

  # Since encrypting and decrypting only differ by subkey order, we can use the same function
  # Take in text as a string of 1s and 0s, and a list of 16 subkeys
  def _transformation(self, text: str, subkeys: list[int]) -> int:
    # Iterate over the text in 64-bit blocks
    # ciphertext = 0
    # for i in range(0, len(text), 64):
    #   print(f"Processing block: '{text[i:i+64]}'")
    #   block = text[i:i+64]
    #   blockInt = int(block, 2)
    #   permutedBlock = self._initialPermutation(blockInt)

    #   leftHalf = (permutedBlock >> 32) & 0xFFFFFFFF
    #   rightHalf = permutedBlock & 0xFFFFFFFF

    #   for subkey in subkeys:
    #     fOutput = self._fFunction(rightHalf, subkey)
    #     newRightHalf = leftHalf ^ fOutput
    #     leftHalf, rightHalf = rightHalf, newRightHalf

    #   combinedBlock = (rightHalf << 32) | leftHalf
    #   finalBlock = self._inverseInitialPermutation(combinedBlock)
    #   ciphertext <<= 64
    #   ciphertext |= finalBlock
    # # Convert the final ciphertext integer back to a string of 1s and 0s
    # ciphertext = f"{ciphertext:b}"
    # return ciphertext

    text = int(text, 2)
    permutedBlock = self._initialPermutation(text)

    leftHalf = (permutedBlock >> 32) & 0xFFFFFFFF
    rightHalf = permutedBlock & 0xFFFFFFFF

    for i, subkey in enumerate(subkeys, 1):
      fOutput = self._fFunction(rightHalf, subkey)
      print(f'f Function Iteration {i:02d}: {fOutput:0{24}b}')
      newRightHalf = leftHalf ^ fOutput
      leftHalf, rightHalf = rightHalf, newRightHalf
      print(f'Left Half  Iteration {i:02d}: {leftHalf:0{24}b}')
      print(f'Right Half Iteration {i:02d}: {rightHalf:0{24}b}')

    combinedBlock = (rightHalf << 32) | leftHalf
    finalBlock = self._inverseInitialPermutation(combinedBlock)
    finalBlock = f"{finalBlock:b}"
    return finalBlock

  # Take in ASCII plaintext and a string key of 1s and 0s, and return the ciphertext as a string of 1s and 0s
  def encrypt(self, plaintext: str, key: str):
    # Implement the DES encryption algorithm
    # Return the ciphertext
    key = int(key, 2)
    subkeys = self.generateSubkeys(key)

    # Convert plaintext to string of 1s and 0s
    plaintextInt = int(plaintext, 2)
    plaintext = f"{plaintextInt:b}"

    ciphertext = self._transformation(plaintext, subkeys)
    return ciphertext

  # Take in the ciphertext as a string of 1s and 0s and a string key of 1s and 0s, and return the plaintext as ASCII text
  def decrypt(self, ciphertext: str, key: str):
    # Implement the DES decryption algorithm
    # Return the plaintext
    key = int(key, 2)
    subkeys = self.generateSubkeys(key)

    # Run the ciphertext through the initial permutation
    plaintext = self._transformation(ciphertext, reversed(subkeys))
    return plaintext

def main():
  parser = argparse.ArgumentParser(
          prog='DES Electronic Codebook (ECB) Cipher',
          description='Allows for encryption and decryption of text using the DES algorithm in ECB mode',
  )
  parser.add_argument('--key', type=str, required=True, help='The key for DES encryption/decryption (key should be a string of 1s and 0s)')
  mode = parser.add_mutually_exclusive_group(required=True)
  mode.add_argument('--encrypt', '-e', action='store_true', help='Encrypt the provided input text (text should be a string of 1s and 0s)')
  mode.add_argument('--decrypt', '-d', action='store_true', help='Decrypt the provided input text (text should be a string of 1s and 0s')
  parser.add_argument('--file', '-f', type=str, default=None, help='The input text to be encrypted or decrypted (text should be a string of 1s and 0s')
  args = parser.parse_args()

  ciphertext: str = None
  if args.file is not None:
    try:
      with open(args.file, 'r') as f:
        ciphertext = f.readline()
    except Exception as e:
      print(f"ERROR: Failed to open file with exception: {e}")
  else:
    ciphertext = input("Please enter your ciphertext: ")
  ciphertext = ciphertext.strip()

  print(f"Cipher text: {ciphertext}")

  des_cipher = DES_ECB_Cipher()
  if args.encrypt:
    result = des_cipher.encrypt(ciphertext, args.key)
    print(f"Encrypted text: {result}")
  elif args.decrypt:
    result = des_cipher.decrypt(ciphertext, args.key)
    print(f"Decrypted text: {result}")

if __name__ == '__main__':
  main()