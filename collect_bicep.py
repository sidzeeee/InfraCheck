import os, shutil

src = r"C:\Users\Siddharth Sarkar\azure-quickstart-templates"
dst = r"C:\Users\Siddharth Sarkar\INFRACHECK\dataset\raw"

os.makedirs(dst, exist_ok=True)

count = 0
for root, dirs, files in os.walk(src):
    for f in files:
        if f.endswith(".bicep"):
            unique_name = root.replace("\\", "_").replace(":", "") + "_" + f
            shutil.copy(os.path.join(root, f), os.path.join(dst, unique_name))
            count += 1

print(f"Collected {count} Bicep files")