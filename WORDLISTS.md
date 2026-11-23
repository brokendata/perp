# External wordlists

perp does not bundle or download wordlists. Use your own authorized inputs.
RockYou is available from the
[Kali wordlists repository](https://gitlab.com/kalilinux/packages/wordlists/-/blob/kali/master/rockyou.txt.gz?ref_type=heads).
Download and extract `rockyou.txt.gz` separately if needed. On Kali, the
`wordlists` apt package also supplies the archive under `/usr/share/wordlists/`.
Keep downloaded inputs outside the project directory.

Run from the project directory, replacing the path with your local file:

```bash
python3 ./perp.py /path/to/rockyou.txt --format plaintext --encoding latin-1 --output-root ./reports
```

The complete wordlist is large: perp holds records in memory and embeds them in
the HTML report. Use a smaller local extract when evaluating the dashboard.
RockYou is dictionary data; it does not establish recovered account credentials
for AttackForge findings. Reports may contain sensitive inputs and should not be
committed or published.
