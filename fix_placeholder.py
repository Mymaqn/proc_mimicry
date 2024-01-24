so_contents = open("./loader.so","rb").read()
main_prog_contents = open("./template.c","r").read()


new_str = ""
for char in so_contents:
    new_str+="\\x"+hex(char)[2:].rjust(2,'0')

main_prog_contents = main_prog_contents.replace("{HIDE_SO_BYTES_PLACEHOLDER}","\"" + new_str + "\"")
main_prog_contents = main_prog_contents.replace("{HIDE_SO_SIZE_PLACEHOLDER}", str(len(so_contents)))

with open("./main.c","w") as f:
    f.write(main_prog_contents)