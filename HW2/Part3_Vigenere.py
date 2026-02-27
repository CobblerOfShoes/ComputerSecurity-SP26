import argparse
import re

# Create a circular buffer from a string
class CircularStrBuffer():
  def __init__(self, string: str):
    self.data = list(string)
    self.size = len(self.data)
    self.curr_pos = 0

  def _increment_position(self):
    self.curr_pos = (self.curr_pos + 1) % self.size

  def next(self):
    result = self.data[self.curr_pos]
    self._increment_position()
    return result

  def __str__(self):
    return "".join(self.data)

class VigenereKasiskiAnalyzer():
  # Frequenices of letters in English text, used for table analysis to guess key letters
  #  Source: https://en.wikipedia.org/wiki/Letter_frequency
  EnglishFrequencies = {
    'A': 0.08167,
    'B': 0.01492,
    'C': 0.02782,
    'D': 0.04253,
    'E': 0.12702,
    'F': 0.02228,
    'G': 0.02015,
    'H': 0.06094,
    'I': 0.06966,
    'J': 0.00153,
    'K': 0.00772,
    'L': 0.04025,
    'M': 0.02406,
    'N': 0.06749,
    'O': 0.07507,
    'P': 0.01929,
    'Q': 0.00095,
    'R': 0.05987,
    'S': 0.06327,
    'T': 0.09056,
    'U': 0.02758,
    'V': 0.00978,
    'W': 0.02360,
    'X': 0.00150,
    'Y': 0.01974,
    'Z': 0.00074,
  }

  # We will use Denning's expected index of coincidence for English text
  DenningExpectedIC = {
    1: 0.0667,
    2: 0.0524,
    3: 0.0454,
    4: 0.0422,
    5: 0.0406,
    6: 0.0397,
    7: 0.0392,
    8: 0.0389,
    9: 0.0387,
    10: 0.0385,
  }

  def __init__(self):
    pass

  # Scan provided ciphertext for repeated letter chains
  def scanCiphertext(self, ciphertext: str):
    minSubstringLen = 3
    maxSubstringLen = 5 # len(ciphertext) // 2
    candidates = {}

    # Remove spaces to allow for substring matching across word boundaries
    ciphertext = ciphertext.replace(' ', '')
    for substringLen in range(minSubstringLen, maxSubstringLen + 1):
      for i in range(len(ciphertext)):
        if i + substringLen > len(ciphertext):
          break
        subtring = ciphertext[i:i+substringLen]
        # Check if substring appears multipe times in the ciphertext
        indicesOfAppearances = [m.start() for m in re.finditer(subtring, ciphertext)]
        numAppearances = len(indicesOfAppearances)
        if numAppearances > 1:
          candidates.update({subtring: (numAppearances, indicesOfAppearances)})

    print(f"Found repeated letter chains in the ciphertext: {candidates}")
    return candidates

  # Apply a given key to decrypt ciphertext
  def decryptCiphertext(self, ciphertext: str, key: str):
    if not key.isalpha():
      print("ERROR: Vigenere keys must be composed of only letters.")
      return None

    key = key.upper()
    circularKey = CircularStrBuffer(key)
    base = ord('A')

    plaintext = ""
    for char in ciphertext:
      if not char.isalpha():
        plaintext += char
        continue
      char = char.upper()
      shiftedValue =( ( ord(char) - base ) - ( ord(circularKey.next()) - base ) ) % 26
      plaintext += chr(shiftedValue + base)

    return plaintext

  # Remove spaces and non-alphabetic characters to allow for substring matching across word boundaries
  def _sanitizeCiphertext(self, ciphertext: str):
    return re.sub(r'[^A-Za-z]', '', ciphertext)

  # Compute the distances between repeated letter chains in the ciphertext
  def _computeDistances(self, ciphertextRepetitions: dict):
    distances = []
    for numAppearances, indicesOfAppearances in ciphertextRepetitions.values():
      for i in range(len(indicesOfAppearances) - 1):
        distance = indicesOfAppearances[i+1] - indicesOfAppearances[i]
        distances.append(distance)
    return distances

  # Find the common factors and their counts across all distances
  def _findCommonFactors(self, distances: list):
    commonFactors = {}
    for distance in distances:
      for i in range(2, distance + 1):
        if distance % i == 0:
          if i not in commonFactors:
            commonFactors[i] = 0
          commonFactors[i] += 1
    return commonFactors

  # Compute the index of coincidence for the given text
  def _computeIC(self, text: str):
    n = len(text)
    if n == 0:
      return 0.0

    frequency = {}
    for char in text:
      if char.isalpha():
        char = char.upper()
        if char not in frequency:
          frequency[char] = 0
        frequency[char] += 1

    ic = sum(count * (count - 1) for count in frequency.values()) / (n * (n - 1))
    return ic

  # Do a table analysis of the ciphertext with an expected key length to guess the key
  def _tableAnalysis(self, ciphertext: str, keyLength: int):
    # Tabulate the ciphertext into keyLength columns
    columns = [[] for _ in range(keyLength)]
    for i, char in enumerate(ciphertext):
      if char.isalpha():
        columns[i % keyLength].append(char.upper())

    # Compute the frequency of each letter in each column
    columnFrequencies = []
    for col in columns:
      freq = {}
      for char in col:
        freq[char] = freq.get(char, 0) + 1
      columnFrequencies.append(freq)
    # Convert each frequency to a percentage of the total letters in the column
    for i in range(len(columnFrequencies)):
      totalLetters = sum(columnFrequencies[i].values())
      for char in columnFrequencies[i]:
        columnFrequencies[i][char] /= totalLetters

    return columnFrequencies

  def _guessKeyFromColumnFrequencies(self, columnFrequencies: list):
    guessedKey = ""
    for colFreq in columnFrequencies:
      bestMatch = None
      bestMatchScore = float('inf')
      for shift in range(26):
        score = 0.0
        for char, freq in colFreq.items():
          shiftedChar = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
          expectedFreq = self.EnglishFrequencies.get(shiftedChar, 0)
          score += abs(freq - expectedFreq)
        if score < bestMatchScore:
          bestMatchScore = score
          bestMatch = shift
      guessedKey += chr(bestMatch + ord('A'))
    return guessedKey

  # Attempt to crack the ciphertext by using repeated chains to guess the key
  def crackCiphertext(self, ciphertext: str):
    ciphertext = self._sanitizeCiphertext(ciphertext)

    # First, scan the ciphertext for repeated letter chains and their indices of appearances
    repetitions = self.scanCiphertext(ciphertext)

    # Attempt to guess the key length by looking at the distances between repeated chains
    distances = self._computeDistances(repetitions)
    print(f"Distances between repeated chains: {distances}")

    # Find all common factors among the distances
    commonFactors = self._findCommonFactors(distances)
    print(f"Common factors among distances: {commonFactors}")

    # Compute the index of coincidence for the ciphertext to help guess the key length
    textIC = self._computeIC(ciphertext)
    print(f"Index of Coincidence for the ciphertext: {textIC}")

    # Find the nearest expected index of coincidence for English text to get expected period
    expectedPeriod = min(self.DenningExpectedIC.keys(), key=lambda k: abs(self.DenningExpectedIC[k] - textIC))
    print(f"Expected period based on index of coincidence: {expectedPeriod}")

    # Then, use the expected period n to tabulate the ciphertext into n columns
    # We will then compute the frequency of letters in each column and compare to expected
    #   frequencies for English text to guess the key letter for each column
    columnFrequencies = self._tableAnalysis(ciphertext, expectedPeriod)
    # print(f"Column frequencies: {columnFrequencies}")

    # Now with column frequencies, we can treat each column as a Caesar cipher and guess
    #   the key letter by comparing to expected frequencies for English text
    guessedKey = self._guessKeyFromColumnFrequencies(columnFrequencies)
    print(f"Guessed key (length {expectedPeriod}): {guessedKey}")

    # In case we were wrong, ask the user if they want to try the other likely key lengths based on common factors
    while True:
      try:
        userInput = input("Do you want to try cracking with another key length based on common factors? (y/n): ")
        if userInput.lower() == 'y':
          # For each common factor (up to 10), do the table analysis and guess the key
          for factor in sorted(commonFactors.keys(), key=lambda k: commonFactors[k], reverse=True):
            if factor > 10:
              break
            print(f"Trying key length {factor} based on common factors...")
            columnFrequencies = self._tableAnalysis(ciphertext, factor)
            guessedKey = self._guessKeyFromColumnFrequencies(columnFrequencies)
            print(f"Guessed key (length {factor}): {guessedKey}")
          break
        else:
          break
      except Exception as e:
        print(f"ERROR: Invalid input with exception: {e}")

    # Then, allow the user to test any key length they want
    while True:
      try:
        userInput = input("Do you want to try cracking with a specific key length? (y/n): ")
        if userInput.lower() == 'y':
          keyLength = int(input("Enter the key length you want to try: "))
          columnFrequencies = self._tableAnalysis(ciphertext, keyLength)
          guessedKey = self._guessKeyFromColumnFrequencies(columnFrequencies)
          print(f"Guessed key (length {keyLength}): {guessedKey}")
        else:
          break
      except Exception as e:
        print(f"ERROR: Invalid input with exception: {e}")


def main():
  parser = argparse.ArgumentParser(
          prog='Vigenere Kasiski Analysis',
          description='Program description',
  )
  modes = parser.add_mutually_exclusive_group()
  modes.add_argument('--scan', '-s', action='store_true',
                      help="Scan the provided ciphertext for repeated letter chains.")
  modes.add_argument('--crack', '-c', action='store_true',
                      help="Attempt to reverse the key of the ciphertext and decrypt it.")
  modes.add_argument('--decrypt', '-d', type=str, default=None,
                      help="Provide a key to use to decrypt the ciphertext.")
  parser.add_argument('--file', '-f', type=str, default=None,
                      help="Provide a filename to read in ciphertext from.")
  args = parser.parse_args()

  analyzer = VigenereKasiskiAnalyzer()

  ciphertext: str = None
  if args.file is not None:
    try:
      with open(args.file, 'r') as f:
        lines = f.readlines()
        ciphertext = "".join(lines)
        ciphertext.replace('\n', ' ')
    except Exception as e:
      print(f"ERROR: Failed to open file with exception: {e}")
  else:
    ciphertext = input("Please enter your ciphertext: ")

  if args.scan:
    analyzer.scanCiphertext(ciphertext)
  if args.crack:
    analyzer.crackCiphertext(ciphertext)
  if args.decrypt is not None:
    plaintext = analyzer.decryptCiphertext(ciphertext, args.decrypt)
    print(f"The plaintext is: {plaintext}")

if __name__ == '__main__':
  main()