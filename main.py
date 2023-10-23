from tkinter import *
from tkinter import messagebox
import base64


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

#save notes
def save_and_encrypt_notes():
    title = title_entry.get()
    message = secret_text.get("1.0",END)
    master_secret = key_entry.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
            messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        message_encrypted = encode(master_secret, message)

        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        except FileNotFoundError:
            with open("mysecret.txt", "w") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        finally:
            title_entry.delete(0, END)
            key_entry.delete(0, END)
            secret_text.delete("1.0",END)

#decrypt notes

def decrypt_notes():
    message_encrypted = secret_text.get("1.0", END)
    master_secret = key_entry.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        try:
            decrypted_message = decode(master_secret,message_encrypted)
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please make sure of encrypted info.")


# Tkinter uygulamasının penceresini oluşturma
window = Tk()
window.minsize(width=400, height=650)
window.config(background="dark grey")
window.title("Secret Notes")

# Yazı fontunu ayarlama
Font_tuple = ("Comic Sans MS", 10, "bold")

# Foto ekleme
photo = PhotoImage(file="images.png")
photo_label = Label(image=photo)
photo_label.pack(pady=5)

#canvas = Canvas(height=180, width=280)
#logo = PhotoImage(file="images.png")
#canvas.create_image(200,200,image=logo)
#canvas.pack()

title_label = Label(text="Enter your title", font=Font_tuple)
title_label.pack(pady=5)

title_entry = Entry()
title_entry.config(width=47)
title_entry.pack(pady=5)

secret_label = Label(text="Enter your secret", font=Font_tuple)
secret_label.pack(pady=5)

secret_text = Text(width=35, height=10)
secret_text.pack(pady=5)

key_label = Label(text="Enter master key", font=Font_tuple)
key_label.pack(pady=5)

key_entry = Entry()
key_entry.config(width=47)
key_entry.pack(pady=5)

save_button = Button(text="Save & Encrypt", bg="black", foreground="white", command=save_and_encrypt_notes)
save_button.pack(pady=5)

decrypt_button = Button(text="Decrypt", bg="black", foreground="white", command=decrypt_notes)
decrypt_button.pack()

window.mainloop()
