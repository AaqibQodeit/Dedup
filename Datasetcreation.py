import os

# create folders
os.makedirs("folder1")
os.makedirs("folder2")

# create unique files in folder1
for i in range(1, 251):
    filename = f"file_{i}.txt"
    with open(f"folder1/{filename}", "w") as f:
        f.write(f"This is file {i} in folder1")

# create identical files in folder1 and folder2
for i in range(1, 251):
    filename = f"file_{i + 250}.txt"
    content = f"This is file {i} in both folders"
    with open(f"folder1/{filename}", "w") as f1, open(f"folder2/{filename}", "w") as f2:
        f1.write(content)
        f2.write(content)

# create unique files in folder2
for i in range(1, 51):
    filename = f"file_{i + 300}.txt"
    with open(f"folder2/{filename}", "w") as f:
        f.write(f"This is file {i} in folder2")
