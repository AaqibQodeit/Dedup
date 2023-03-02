import resource
import os
import hashlib
import sqlite3
from phe import paillier
from bloom_filter import BloomFilter
from concurrent.futures import ThreadPoolExecutor
from Crypto.Util.number import getPrime, bytes_to_long
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor
from bloom_filter import BloomFilter
from typing import List
import time

# Set resource limits to unlimited to avoid hitting limits during testing
cpu_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime + resource.getrusage(resource.RUSAGE_SELF).ru_stime
max_resident_set_size = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
num_page_faults = resource.getrusage(resource.RUSAGE_SELF).ru_majflt
num_voluntary_context_switches = resource.getrusage(resource.RUSAGE_SELF).ru_nvcsw
num_involuntary_context_switches = resource.getrusage(resource.RUSAGE_SELF).ru_nivcsw


# Start measuring time and memory usage
start_time = time.monotonic()
start_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

# Run the code block you want to measure
# (replace this with your actual code)
class ABHE:
    def __init__(self):
        self.p = getPrime(1024)
        self.g = 2
        self.sk = get_random_bytes(16)
        self.pk = pow(self.g, bytes_to_long(self.sk), self.p)

    def encrypt(self, message, attrs):
        r = bytes_to_long(get_random_bytes(16))
        s = pow(self.g, r, self.p)
        t = pow(self.pk, r, self.p)
        for attr in attrs:
            t *= pow(bytes_to_long(hashlib.sha256(attr.encode()).digest()), r, self.p)
            t %= self.p
        ct = (s, message * t % self.p)
        return ct

    def decrypt(self, ct, attr):
        s, u = ct
        v = pow(s, bytes_to_long(self.sk), self.p)
        for a in attr:
            v *= pow(bytes_to_long(hashlib.sha256(a.encode()).digest()), self.p - bytes_to_long(self.sk), self.p)
            v %= self.p
        return u * pow(v, self.p - 2, self.p) % self.p

class ClientDeduplicator:
    def __init__(self, abhe, db_path):
        self.abhe = abhe
        self.db_path = db_path
        self.bf_size = 1000000 # bloom filter size
        self.bf_fpr = 0.01 # bloom filter false positive rate
        self.bf = BloomFilter(self.bf_size, self.bf_fpr)
        self.pool = ThreadPoolExecutor(max_workers=os.cpu_count())

        # Connect to the database and create the hashes table if it doesn't exist
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hashes (
                id INTEGER PRIMARY KEY,
                encrypted_hash TEXT UNIQUE,
                file_path TEXT
            )
        """)
        conn.commit()
        conn.close()

    def _hash_file(self, path):
        BLOCKSIZE = 65536
        hasher = hashlib.sha256()
        with open(path, 'rb') as file:
            buffer = file.read(BLOCKSIZE)
            while len(buffer) > 0:
                hasher.update(buffer)
                buffer = file.read(BLOCKSIZE)
        return hasher.digest()

    def _encrypt_hash(self, attrs):
        encrypted_hash = self.abhe.encrypt(1, attrs)
        return str(encrypted_hash)
    
    def _deduplicate_files(self, files, policy):
      conn = sqlite3.connect(self.db_path)
      cursor = conn.cursor()

      insert_query = "INSERT INTO hashes (encrypted_hash, file_path) VALUES (?, ?)"
      batch_size = 1000
      insert_buffer = []

      for file in files:
          path = file['path']
          hash = self._hash_file(path)
          attrs = policy.get_file_attributes(path)
          encrypted_hash_str = self._encrypt_hash(attrs)

          # Check if the encrypted hash is already in the bloom filter
          if encrypted_hash_str not in self.bf:
              # Check if the encrypted hash is already in the database
              cursor.execute("SELECT file_path, encrypted_hash FROM hashes WHERE encrypted_hash = ?", (encrypted_hash_str,))
              result = cursor.fetchone()
              if result is not None:
                  if self._hash_file(result[0]) == hash:
                      print(f"Skipping duplicate file {path}")
                      continue
                  else:
                      print(f"Replacing file {path} with reference to {result[0]}")
                      cursor.execute("UPDATE hashes SET file_path = ? WHERE encrypted_hash = ?", (path, encrypted_hash_str))
              else:
                  # Add the encrypted hash and file path to the insert buffer
                  insert_buffer.append((encrypted_hash_str, path))

                  # Add the encrypted hash to the bloom filter
                  self.bf.add(encrypted_hash_str)

          # Flush the insert buffer if it has reached the batch size
          if len(insert_buffer) >= batch_size:
              cursor.executemany(insert_query, insert_buffer)
              conn.commit()
              insert_buffer = []

      # Insert any remaining rows in the buffer
      if len(insert_buffer) > 0:
          cursor.executemany(insert_query, insert_buffer)
          conn.commit()

      conn.close()


    def deduplicate(self, files, policy):
        futures = []
        batch_size = 1000
        for i in range(0, len(files), batch_size):
            batch = files[i:i+batch_size]
            future = self.pool.submit(self._deduplicate_files, batch, policy)
            futures.append(future)

        for future in futures:
            future.result()

class FilePolicy:
  def __init__(self, attr_func):
        self.attr_func = attr_func

  def get_file_attributes(self, path):
      return self.attr_func(path)

def get_file_attrs(path):
    return ['extension:' + os.path.splitext(path)[1]]

def main():
    abhe = ABHE()
    policy = FilePolicy(get_file_attrs)
    deduplicator = ClientDeduplicator(abhe, 'hashes.db')

    # Set the path to the directory you want to deduplicate
    directory_path = '/content/folder2'
    
    files = []
    for root, dirs, files_in_dir in os.walk(directory_path):
        for file_name in files_in_dir:
            file_path = os.path.join(root, file_name)
            files.append({'path': file_path})

    deduplicator.deduplicate(files, policy)

if __name__ == '__main__':
    main()
# End measuring time and memory usage
end_time = time.monotonic()
end_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

# Print the results
print(f"CPU time used: {cpu_time:.2f} seconds")
print(f"Max resident set size: {max_resident_set_size} bytes")
print(f"Number of page faults: {num_page_faults}")
print(f"Number of voluntary context switches: {num_voluntary_context_switches}")
print(f"Number of involuntary context switches: {num_involuntary_context_switches}")
