import os

class Junky:

    def __init__(self, exts):
        self.exts = exts

    def getJunkFiles(self, path):
        all_files = [p for p in os.listdir(path) if os.path.isfile(os.path.join(path, p))]
        junkfiles = filter(self.findJunk, all_files )
        return list(junkfiles)

    def findJunk(self, f):
        print(self.exts)
        for ext in self.exts:
            if ext:
                return f.endswith(ext)




def makeList(records):
    return [rec.extension for rec in records]

if __name__ == "__main__":
    jun = junky()
    print(jun.getJunkFiles('./junk_files'))