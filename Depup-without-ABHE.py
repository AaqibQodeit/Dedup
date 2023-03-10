import os
import hashlib
import shutil
import time
import resource

cpu_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime + resource.getrusage(resource.RUSAGE_SELF).ru_stime
max_resident_set_size = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
num_page_faults = resource.getrusage(resource.RUSAGE_SELF).ru_majflt
num_voluntary_context_switches = resource.getrusage(resource.RUSAGE_SELF).ru_nvcsw
num_involuntary_context_switches = resource.getrusage(resource.RUSAGE_SELF).ru_nivcsw

def deduplicate_directory(source_dir, dest_dir):
    """
    Deduplicates files in a directory by comparing their content hashes.

    Args:
        source_dir (str): Path to the source directory.
        dest_dir (str): Path to the destination directory where deduplicated files will be stored.

    Returns:
        None
    """
    # Create the destination directory if it doesn't exist
    os.makedirs(dest_dir, exist_ok=True)

    # Keep track of file hashes and their corresponding paths
    file_hashes = {}

    # Traverse the source directory and compare the content hashes of each file
    start_time = time.time()
    for dirpath, dirnames, filenames in os.walk(source_dir):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)

            # Compute the content hash of the file
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            # Check if the file hash already exists
            if file_hash in file_hashes:
                # If the file hash exists, it means we already have a copy of this file
                # in the destination directory, so we can skip copying it again.
                print(f'Skipping duplicate file: {file_path}')
                continue

            # If the file hash doesn't exist, it means we need to copy the file to the destination directory
            file_hashes[file_hash] = file_path
            dest_file_path = os.path.join(dest_dir, filename)
            shutil.copyfile(file_path, dest_file_path)
            

    end_time = time.time()
    print(f"CPU time used: {cpu_time:.2f} seconds")
    print(f"Max resident set size: {max_resident_set_size} bytes")
    print(f"Number of page faults: {num_page_faults}")
    print(f"Number of voluntary context switches: {num_voluntary_context_switches}")
    print(f"Number of involuntary context switches: {num_involuntary_context_switches}")
    
deduplicate_directory('/content/folder2', '/content/folder1')
