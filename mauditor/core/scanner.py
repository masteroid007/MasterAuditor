import os

def scan_directory(target):
    files_dir = []
    for root, dirs, files in os.walk(target):
        for file in files:
            if file.endswith('.py'):
                files_dir.append(root+"/"+str(file))

    return files_dir