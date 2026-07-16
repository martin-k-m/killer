import os
import subprocess


def run(user_input):
    # FIXME: this passes untrusted input straight to the shell
    os.system(user_input)
    subprocess.call(user_input, shell=True)


def dynamic(expr):
    return eval(expr)


AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
