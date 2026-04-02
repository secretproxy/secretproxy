Output demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1100
Set Height 600
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 30ms

Sleep 300ms
Type `# What you paste into your AI coding agent:`
Enter
Type `echo "debug this config: STRIPE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc and DATABASE=postgres://admin:p4ssw0rd@prod.db:5432/users"`
Enter
Sleep 2s
Enter

Type `# What the LLM API actually receives (through secretproxy):`
Enter
Type `secretproxy check "debug this config: STRIPE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc and DATABASE=postgres://admin:p4ssw0rd@prod.db:5432/users"`
Enter
Sleep 5s
